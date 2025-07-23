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
# RenderのDATABASE_URL形式に対応
db_url = os.environ.get('DATABASE_URL', 'sqlite:///test.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
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
    status = db.Column(db.String(20), default='available')
    current_session_id = db.Column(db.String(100))
    guest_count = db.Column(db.Integer, default=0)
    x = db.Column(db.Float, default=0)
    y = db.Column(db.Float, default=0)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
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
        if self.used: return False
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
        if 'qr_token' in session:
            token = QRToken.query.filter_by(token=session['qr_token']).first()
            if token and token.is_valid():
                return f(*args, **kwargs)
        
        if current_user.is_authenticated:
             return f(*args, **kwargs)

        flash('このページにアクセスするにはQRコードのスキャンが必要です。', 'warning')
        return redirect(url_for('index'))
    return decorated_function

# --- ログインマネージャー ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ルート定義 ---

@app.route('/')
def index():
    # 誰でもアクセス可能にする
    return render_template('index.html')

@app.route('/qr/<token>')
def qr_auth(token):
    qr_token = QRToken.query.filter_by(token=token).first()
    if not qr_token or not qr_token.is_valid():
        flash('このQRコードは無効または期限切れです。', 'danger')
        return redirect(url_for('index'))
    
    session['qr_token'] = token
    session.permanent = True
    
    table = Table.query.filter_by(name=qr_token.table_name).first()
    if not table:
        table = Table(
            name=qr_token.table_name,
            status='occupied',
            current_session_id=token,
            guest_count=qr_token.guest_count
        )
        db.session.add(table)
    else:
        table.status = 'occupied'
        table.current_session_id = token
        table.guest_count = qr_token.guest_count
        
    qr_token.used = True
    db.session.commit()
    
    return redirect(url_for('table_menu', table_id=table.id))

@app.route('/table/<int:table_id>')
@require_qr_token
def table_menu(table_id):
    table = Table.query.get_or_404(table_id)
    menu_items = MenuItem.query.filter_by(active=True).order_by(MenuItem.category, MenuItem.name).all()
    
    # カテゴリごとにメニューを整理
    categorized_menu = {}
    for item in menu_items:
        if item.category not in categorized_menu:
            categorized_menu[item.category] = []
        categorized_menu[item.category].append(item)
        
    return render_template('table_menu.html', table=table, categorized_menu=categorized_menu)

# --- 管理者ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=request.form.get('remember_me'))
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        flash('ユーザー名またはパスワードが違います。', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('logged_in', None)
    flash('ログアウトしました。', 'success')
    return redirect(url_for('login'))

@app.route('/kitchen')
@login_required
def kitchen():
    return render_template('kitchen.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
    
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
def delete_menu_item_get(item_id):
    item = MenuItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        return jsonify(success=True, message='メニューを削除しました。')
    return jsonify(success=False, message='メニューが見つかりません。'), 404
    
@app.route('/admin/menu/toggle/<int:item_id>')
@login_required
def toggle_menu_item_get(item_id):
    item = MenuItem.query.get(item_id)
    if item:
        item.active = not item.active
        db.session.commit()
        return jsonify(success=True, message='表示状態を切り替えました。', active=item.active)
    return jsonify(success=False, message='メニューが見つかりません。'), 404

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
def delete_table_get(table_id):
    table = Table.query.get(table_id)
    if table:
        db.session.delete(table)
        db.session.commit()
        return jsonify(success=True, message='テーブルを削除しました。')
    return jsonify(success=False, message='テーブルが見つかりません。'), 404

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

@app.route('/admin/history')
@login_required
def admin_history():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_history.html', tables=tables)

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    return render_template('admin_guidance.html')


# --- API エンドポイント ---

@app.route('/api/order/submit', methods=['POST'])
@require_qr_token
def submit_order():
    data = request.get_json()
    table_id = data.get('table_id')
    cart_items = data.get('items', {})
    
    table = Table.query.get(table_id)
    if not table or not cart_items:
        return jsonify(success=False, message="無効なデータです"), 400

    for item_id, item_data in cart_items.items():
        menu_item = MenuItem.query.get(item_id)
        if menu_item:
            menu_item.popularity_count += item_data['quantity']
            for _ in range(item_data['quantity']):
                new_order = Order(
                    item_name=item_data['name'],
                    item_price=item_data['price'],
                    table_id=table_id,
                    session_id=session.get('qr_token')
                )
                db.session.add(new_order)
    
    db.session.commit()
    return jsonify(success=True, message="注文を受け付けました。")

@app.route('/api/stats/dashboard')
@login_required
def api_stats_dashboard():
    today_start = datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    
    today_sales = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp >= today_start).scalar() or 0
    order_count = Order.query.filter(Order.timestamp >= today_start).count()
    
    table_stats = dict(db.session.query(Table.status, func.count(Table.id)).group_by(Table.status).all())
    
    popular_items = MenuItem.query.order_by(MenuItem.popularity_count.desc()).limit(5).all()
    
    return jsonify({
        'today_sales': today_sales,
        'order_count': order_count,
        'table_stats': table_stats,
        'popular_items': [{'name': item.name, 'count': item.popularity_count} for item in popular_items]
    })

@app.route('/api/dashboard/sales')
@login_required
def api_dashboard_sales():
    period = request.args.get('period', 'daily')
    labels = []
    sales = []
    
    if period == 'daily':
        for i in range(7):
            day = datetime.date.today() - datetime.timedelta(days=i)
            day_start = datetime.datetime.combine(day, datetime.time.min).replace(tzinfo=JST)
            day_end = datetime.datetime.combine(day, datetime.time.max).replace(tzinfo=JST)
            daily_total = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp.between(day_start, day_end)).scalar() or 0
            labels.append(day.strftime('%m/%d'))
            sales.append(daily_total)
        labels.reverse()
        sales.reverse()
    else: # monthly
        for i in range(6):
            month_date = datetime.date.today() - datetime.timedelta(days=i*30)
            month_start = month_date.replace(day=1)
            next_month = (month_start + datetime.timedelta(days=32)).replace(day=1)
            month_end = next_month - datetime.timedelta(days=1)
            
            monthly_total = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp.between(month_start, month_end)).scalar() or 0
            labels.append(month_start.strftime('%Y/%m'))
            sales.append(monthly_total)
        labels.reverse()
        sales.reverse()

    return jsonify({'labels': labels, 'sales': sales})

@app.route('/api/history/orders')
@login_required
def api_history_orders():
    orders_query = db.session.query(Order, Table.name).join(Table, Order.table_id == Table.id).order_by(Order.timestamp.desc()).all()
    
    orders_data = [{
        'id': order.id,
        'table_name': table_name,
        'table_id': order.table_id,
        'item_name': order.item_name,
        'item_price': order.item_price,
        'status': order.status,
        'timestamp': order.timestamp.isoformat(),
        'session_id': order.session_id
    } for order, table_name in orders_query]
    
    return jsonify(orders=orders_data)

@app.route('/api/menu/update_full', methods=['POST'])
@login_required
def api_menu_update_full():
    data = request.json
    item = MenuItem.query.get(data['id'])
    if item:
        item.name = data['name']
        item.price = data['price']
        item.category = data['category']
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/api/menu/import', methods=['POST'])
@login_required
def api_menu_import():
    data = request.json
    items = data.get('items', [])
    count = 0
    for item_data in items:
        new_item = MenuItem(
            name=item_data['name'],
            price=item_data['price'],
            category=item_data['category']
        )
        db.session.add(new_item)
        count += 1
    db.session.commit()
    return jsonify(success=True, count=count)

@app.route('/api/tables/save_positions', methods=['POST'])
@login_required
def api_save_table_positions():
    data = request.json
    tables_data = data.get('tables', [])
    for table_data in tables_data:
        table = Table.query.get(table_data['id'])
        if table:
            table.x = table_data['x']
            table.y = table_data['y']
    db.session.commit()
    return jsonify(success=True)

# --- データベース初期化 ---
@app.cli.command("init-db")
def init_db_command():
    """データベースをクリアし、初期データを投入します。"""
    db.drop_all()
    db.create_all()
    
    # 管理者ユーザー作成
    admin_user = User(username='admin', is_admin=True)
    admin_user.set_password('password123') # 本番環境ではもっと複雑なパスワードを使用してください
    db.session.add(admin_user)
    
    # ダミーデータ
    tables = [Table(name=f'{i}番テーブル') for i in range(1, 6)]
    db.session.add_all(tables)
    
    menu_items = [
        MenuItem(name='シーザーサラダ', price=800, category='前菜'),
        MenuItem(name='ステーキ', price=2500, category='メイン'),
        MenuItem(name='カルボナーラ', price=1200, category='パスタ'),
    ]
    db.session.add_all(menu_items)

    db.session.commit()
    print("データベースが初期化されました。")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('password123')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created.")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)