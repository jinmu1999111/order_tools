import os
import datetime
import secrets
import json
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, desc
import pytz

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', '').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)

db = SQLAlchemy(app)
JST = pytz.timezone('Asia/Tokyo')

# --- ログイン機能の設定 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "このページにアクセスするにはログインが必要です。"

# --- データベースモデルの定義 ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    active = db.Column(db.Boolean, default=True)
    popularity_count = db.Column(db.Integer, default=0)

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='available')  # available, occupied, cleaning
    current_session_id = db.Column(db.String(100))
    guest_count = db.Column(db.Integer, default=0)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, cooking, served, cancelled
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(JST))
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    session_id = db.Column(db.String(100))
    notified = db.Column(db.Boolean, default=False)

class QRToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    table_name = db.Column(db.String(100))
    guest_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(JST))
    used = db.Column(db.Boolean, default=False)
    
    def is_valid(self):
        if self.used:
            return False
        expiry = self.created_at + datetime.timedelta(minutes=30)
        return datetime.datetime.now(JST) < expiry

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    endpoint = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(JST))
    suspicious = db.Column(db.Boolean, default=False)

# --- セキュリティデコレータ ---
def require_qr_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 管理者は除外
        if current_user.is_authenticated:
            return f(*args, **kwargs)
            
        # QRトークンチェック
        if 'qr_token' not in session:
            abort(403)
        
        token = QRToken.query.filter_by(token=session['qr_token']).first()
        if not token or not token.is_valid():
            session.pop('qr_token', None)
            abort(403)
            
        return f(*args, **kwargs)
    return decorated_function

def log_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        log = AccessLog(
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500],
            endpoint=request.endpoint
        )
        
        # 不審なアクセスパターンをチェック
        recent_count = AccessLog.query.filter_by(
            ip_address=request.remote_addr
        ).filter(
            AccessLog.timestamp > datetime.datetime.now(JST) - datetime.timedelta(minutes=1)
        ).count()
        
        if recent_count > 30:  # 1分間に30回以上のアクセス
            log.suspicious = True
            
        db.session.add(log)
        db.session.commit()
        
        return f(*args, **kwargs)
    return decorated_function

# --- ログインマネージャー ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- QRコード認証エンドポイント ---
@app.route('/qr/<token>')
@log_access
def qr_auth(token):
    qr_token = QRToken.query.filter_by(token=token).first()
    
    if not qr_token or not qr_token.is_valid():
        flash('このQRコードは無効または期限切れです。', 'danger')
        return render_template('error.html'), 403
    
    # トークンをセッションに保存
    session['qr_token'] = token
    session.permanent = True
    
    # 案内管理用のQRコードの場合
    if qr_token.table_name and not qr_token.used:
        # 新しいテーブルを作成
        existing = Table.query.filter_by(name=qr_token.table_name).first()
        if not existing:
            new_table = Table(
                name=qr_token.table_name,
                status='occupied',
                current_session_id=token,
                guest_count=qr_token.guest_count
            )
            db.session.add(new_table)
            qr_token.used = True
            db.session.commit()
            
            return redirect(url_for('table_menu', table_id=new_table.id))
    
    # 通常のテーブルQRコード
    return redirect(url_for('index'))

# --- Webページのルート ---
@app.route('/')
@require_qr_token
@log_access
def index():
    tables = Table.query.filter_by(status='occupied').order_by(Table.name).all()
    return render_template('index.html', tables=tables)

@app.route('/table/<int:table_id>')
@require_qr_token
@log_access
def table_menu(table_id):
    table = Table.query.get_or_404(table_id)
    
    # セッションチェック
    if table.current_session_id and table.current_session_id != session.get('qr_token'):
        abort(403)
    
    menu_items = MenuItem.query.filter_by(active=True).order_by(MenuItem.category, MenuItem.name).all()
    
    categorized_menu = {}
    for item in menu_items:
        if item.category not in categorized_menu:
            categorized_menu[item.category] = []
        
        item_data = {
            'id': item.id,
            'name': item.name,
            'price': item.price,
            'category': item.category
        }
        categorized_menu[item.category].append(item_data)
        
    return render_template('table_menu.html', table=table, categorized_menu=categorized_menu)

# --- API ---
@app.route('/api/order/submit', methods=['POST'])
@require_qr_token
def submit_order():
    data = request.get_json()
    table_id = data.get('table_id')
    cart_items = data.get('cart', [])
    table = Table.query.get(table_id)

    if not table or not cart_items:
        return jsonify(success=False, message="Invalid data"), 400

    for item in cart_items:
        # 人気度カウントを更新
        menu_item = MenuItem.query.filter_by(name=item['name']).first()
        if menu_item:
            menu_item.popularity_count += 1
            
        new_order = Order(
            item_name=item['name'],
            item_price=item['price'],
            table_id=table_id,
            session_id=session.get('qr_token')
        )
        db.session.add(new_order)
        
    table.status = 'occupied'
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/table_status/<int:table_id>')
@require_qr_token
def table_status(table_id):
    table = Table.query.get_or_404(table_id)
    session_id = session.get('qr_token')
    
    orders = table.orders.filter_by(session_id=session_id).order_by(Order.timestamp.desc()).all()
    total_price = sum(order.item_price for order in orders)
    
    orders_data = [{
        'id': o.id, 
        'name': o.item_name, 
        'status': o.status,
        'status_display': {
            'pending': '注文受付',
            'cooking': '調理中',
            'served': '提供済',
            'cancelled': 'キャンセル'
        }.get(o.status, o.status)
    } for o in orders]
    
    return jsonify(orders=orders_data, total_price=total_price)

@app.route('/api/order/update_status', methods=['POST'])
@login_required
def update_order_status():
    data = request.get_json()
    order_id = data.get('order_id')
    new_status = data.get('status')
    
    if new_status not in ['pending', 'cooking', 'served', 'cancelled']:
        return jsonify(success=False), 400
        
    order = Order.query.get(order_id)
    if order:
        order.status = new_status
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/api/kitchen_status')
@login_required
def kitchen_status():
    status_filter = request.args.get('status', 'pending')
    
    query = db.session.query(Order, Table).join(Table)
    
    if status_filter != 'all':
        query = query.filter(Order.status == status_filter)
        
    orders = query.order_by(Order.timestamp).all()
    
    orders_data = []
    new_orders = []
    
    for order, table in orders:
        order_data = {
            'id': order.id,
            'item_name': order.item_name,
            'timestamp': order.timestamp.strftime('%H:%M:%S'),
            'table_id': table.id,
            'table_name': table.name,
            'status': order.status,
            'minutes_ago': int((datetime.datetime.now(JST) - order.timestamp).total_seconds() / 60)
        }
        orders_data.append(order_data)
        
        # 未通知の新規注文をチェック
        if order.status == 'pending' and not order.notified:
            new_orders.append(order.id)
            order.notified = True
            
    if new_orders:
        db.session.commit()
        
    return jsonify(orders=orders_data, new_orders=new_orders)

@app.route('/api/stats/dashboard')
@login_required
def stats_dashboard():
    # 本日の統計
    today = datetime.datetime.now(JST).date()
    today_start = datetime.datetime.combine(today, datetime.time.min).replace(tzinfo=JST)
    today_end = datetime.datetime.combine(today, datetime.time.max).replace(tzinfo=JST)
    
    # 売上統計
    today_orders = Order.query.filter(
        Order.timestamp >= today_start,
        Order.timestamp <= today_end
    ).all()
    
    total_sales = sum(order.item_price for order in today_orders)
    order_count = len(today_orders)
    
    # 人気メニュートップ5
    popular_items = db.session.query(
        MenuItem.name,
        MenuItem.popularity_count
    ).order_by(desc(MenuItem.popularity_count)).limit(5).all()
    
    # テーブル稼働状況
    table_stats = db.session.query(
        Table.status,
        func.count(Table.id)
    ).group_by(Table.status).all()
    
    return jsonify({
        'today_sales': total_sales,
        'order_count': order_count,
        'popular_items': [{'name': item[0], 'count': item[1]} for item in popular_items],
        'table_stats': dict(table_stats)
    })

# --- 管理者用ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('kitchen'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('kitchen'))
        flash('ユーザー名またはパスワードが違います。', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/kitchen')
@login_required
def kitchen():
    return render_template('kitchen.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    pending_tokens = QRToken.query.filter_by(used=False).filter(
        QRToken.created_at > datetime.datetime.now(JST) - datetime.timedelta(minutes=30)
    ).order_by(desc(QRToken.created_at)).all()
    return render_template('admin_guidance.html', pending_tokens=pending_tokens)

@app.route('/admin/guidance/create', methods=['POST'])
@login_required
def create_guidance():
    table_name = request.form.get('table_name')
    guest_count = int(request.form.get('guest_count', 1))
    
    # トークンを生成
    token = secrets.token_urlsafe(32)
    qr_token = QRToken(
        token=token,
        table_name=table_name,
        guest_count=guest_count
    )
    db.session.add(qr_token)
    db.session.commit()
    
    flash(f'案内QRコードを生成しました: {table_name} ({guest_count}名)', 'success')
    return redirect(url_for('admin_guidance'))

@app.route('/admin/guidance/complete/<int:token_id>', methods=['POST'])
@login_required
def complete_guidance(token_id):
    qr_token = QRToken.query.get_or_404(token_id)
    
    if qr_token.used:
        flash('このQRコードは既に使用されています。', 'warning')
        return redirect(url_for('admin_guidance'))
    
    # テーブルを作成
    table = Table(
        name=qr_token.table_name,
        status='occupied',
        current_session_id=qr_token.token,
        guest_count=qr_token.guest_count
    )
    db.session.add(table)
    qr_token.used = True
    db.session.commit()
    
    flash(f'テーブル「{qr_token.table_name}」を作成し、案内を完了しました。', 'success')
    return redirect(url_for('admin_tables'))

@app.route('/admin/history')
@login_required
def admin_history():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_history.html', tables=tables, Order=Order)

@app.route('/admin/history/clear/<int:table_id>', methods=['POST'])
@login_required
def clear_history(table_id):
    table = Table.query.get_or_404(table_id)
    table.orders.delete()
    table.status = 'cleaning'
    table.current_session_id = None
    table.guest_count = 0
    db.session.commit()
    flash(f'テーブル「{table.name}」の注文履歴を削除し、清掃中に設定しました。', 'success')
    return redirect(url_for('admin_history'))

@app.route('/admin/menu')
@login_required
def admin_menu():
    menu_items = MenuItem.query.order_by(MenuItem.category, MenuItem.name).all()
    return render_template('admin_menu.html', menu_items=menu_items)

@app.route('/admin/menu/add', methods=['POST'])
@login_required
def add_menu_item():
    new_item = MenuItem(
        name=request.form.get('name'), 
        price=int(request.form.get('price')), 
        category=request.form.get('category')
    )
    db.session.add(new_item)
    db.session.commit()
    flash('メニューを追加しました。', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/menu/delete/<int:item_id>')
@login_required
def delete_menu_item(item_id):
    item = MenuItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('メニューを削除しました。', 'success')
    return redirect(url_for('admin_menu'))
    
@app.route('/admin/menu/toggle/<int:item_id>')
@login_required
def toggle_menu_item(item_id):
    item = MenuItem.query.get(item_id)
    if item:
        item.active = not item.active
        db.session.commit()
        flash('表示状態を切り替えました。', 'info')
    return redirect(url_for('admin_menu'))

@app.route('/admin/tables')
@login_required
def admin_tables():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_tables.html', tables=tables)

@app.route('/admin/tables/add', methods=['POST'])
@login_required
def add_table():
    table_name = request.form.get('name')
    if table_name and not Table.query.filter_by(name=table_name).first():
        new_table = Table(name=table_name)
        db.session.add(new_table)
        db.session.commit()
        flash(f'テーブル「{table_name}」を追加しました。', 'success')
    else:
        flash(f'テーブル「{table_name}」は既に存在するか、名前が空です。', 'danger')
    return redirect(url_for('admin_tables'))

@app.route('/admin/tables/delete/<int:table_id>')
@login_required
def delete_table(table_id):
    table = Table.query.get(table_id)
    if table:
        db.session.delete(table)
        db.session.commit()
        flash('テーブルを削除しました。', 'success')
    return redirect(url_for('admin_tables'))

@app.route('/admin/tables/update_status/<int:table_id>', methods=['POST'])
@login_required
def update_table_status(table_id):
    table = Table.query.get_or_404(table_id)
    new_status = request.form.get('status')
    
    if new_status in ['available', 'occupied', 'cleaning']:
        table.status = new_status
        if new_status == 'available':
            table.current_session_id = None
            table.guest_count = 0
        db.session.commit()
        flash(f'テーブル「{table.name}」のステータスを更新しました。', 'success')
    
    return redirect(url_for('admin_tables'))

# --- アプリ起動時にデータベースを自動作成 ---
with app.app_context():
    # まず、全てのテーブルを作成する
    db.create_all()
    print("Database tables created or already exist.")

    # 次に、管理者ユーザーの存在を確認して作成する
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('password123')
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created.")

# --- アプリケーションの実行 ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)