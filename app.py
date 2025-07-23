import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import json

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)
app.secret_key = os.urandom(24)
# Renderの環境変数からデータベースURLを読み込み、互換性のため先頭を書き換える
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', '').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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
    allowed_ips = db.Column(db.Text)  # JSON形式でIPリストを保存

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_allowed_ips(self):
        if self.allowed_ips:
            return json.loads(self.allowed_ips)
        return []
    
    def set_allowed_ips(self, ip_list):
        self.allowed_ips = json.dumps(ip_list)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    active = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text)  # メニュー説明
    image_url = db.Column(db.String(255))  # 画像URL

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='available')  # available, occupied, cleaning, reserved
    capacity = db.Column(db.Integer, default=4)  # 席数
    current_guests = db.Column(db.Integer, default=0)  # 現在の利用人数
    last_updated = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=1)  # 数量
    status = db.Column(db.String(20), default='pending')  # pending, preparing, ready, served
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    notes = db.Column(db.Text)  # 特別要望
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)

class GuestSession(db.Model):
    """案内管理用の一時テーブル"""
    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(100), unique=True, nullable=False)
    table_name = db.Column(db.String(100), nullable=False)
    guest_count = db.Column(db.Integer, nullable=False)
    qr_generated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime)  # QRコードの有効期限
    status = db.Column(db.String(20), default='waiting')  # waiting, seated, expired
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class AccessLog(db.Model):
    """アクセスログ"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    endpoint = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_suspicious = db.Column(db.Boolean, default=False)

# --- ログインマネージャー ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- セキュリティミドルウェア ---
def log_access(endpoint, is_suspicious=False):
    """アクセスログを記録"""
    try:
        log = AccessLog(
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            endpoint=endpoint,
            is_suspicious=is_suspicious
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass  # ログ記録エラーは無視

def check_guest_access():
    """お客様用ページのアクセス制御"""
    # セッショントークンまたは直接QRアクセスかをチェック
    token = request.args.get('token') or session.get('guest_token')
    if token:
        guest_session = GuestSession.query.filter_by(session_token=token).first()
        if guest_session and guest_session.expires_at > datetime.datetime.utcnow():
            session['guest_token'] = token
            session['table_name'] = guest_session.table_name
            return True
    return False

# --- お客様向けページ（セキュリティ強化版） ---
@app.route('/')
def index():
    # お客様用のトップページは案内QRからのアクセスのみ許可
    if not check_guest_access():
        log_access('unauthorized_index_access', is_suspicious=True)
        return render_template('access_denied.html'), 403
    
    # 案内済みの場合、直接メニューページにリダイレクト
    token = session.get('guest_token')
    guest_session = GuestSession.query.filter_by(session_token=token).first()
    if guest_session and guest_session.status == 'seated':
        table = Table.query.filter_by(name=guest_session.table_name).first()
        if table:
            return redirect(url_for('table_menu', table_id=table.id, token=token))
    
    return render_template('guest_waiting.html')

@app.route('/menu/<token>')
def direct_menu_access(token):
    """QRコードからの直接メニューアクセス"""
    guest_session = GuestSession.query.filter_by(session_token=token).first()
    
    if not guest_session or guest_session.expires_at < datetime.datetime.utcnow():
        return render_template('qr_expired.html'), 404
    
    if guest_session.status != 'seated':
        return render_template('not_seated_yet.html'), 403
    
    # テーブルを確認
    table = Table.query.filter_by(name=guest_session.table_name).first()
    if not table:
        return render_template('table_not_found.html'), 404
    
    session['guest_token'] = token
    session['table_name'] = guest_session.table_name
    return redirect(url_for('table_menu', table_id=table.id))

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    # セキュリティチェック
    if not check_guest_access():
        log_access(f'unauthorized_table_access_{table_id}', is_suspicious=True)
        abort(403)
    
    table = Table.query.get_or_404(table_id)
    
    # セッションのテーブル名と一致するかチェック
    if session.get('table_name') != table.name:
        log_access(f'table_mismatch_access_{table_id}', is_suspicious=True)
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
            'category': item.category,
            'description': item.description or '',
            'image_url': item.image_url or ''
        }
        categorized_menu[item.category].append(item_data)
        
    return render_template('table_menu.html', table=table, categorized_menu=categorized_menu)

# --- API ---
@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    if not check_guest_access():
        return jsonify(success=False, message="Access denied"), 403
    
    data = request.get_json()
    table_id = data.get('table_id')
    cart_items = data.get('cart', [])
    notes = data.get('notes', '')
    
    table = Table.query.get(table_id)
    
    # セッションのテーブル名と一致するかチェック
    if not table or session.get('table_name') != table.name:
        return jsonify(success=False, message="Invalid table access"), 403

    if not cart_items:
        return jsonify(success=False, message="Cart is empty"), 400

    try:
        for item in cart_items:
            new_order = Order(
                item_name=item['name'],
                item_price=item['price'],
                quantity=item.get('quantity', 1),
                notes=notes,
                table_id=table_id
            )
            db.session.add(new_order)
        
        # テーブルステータスを更新
        table.status = 'occupied'
        table.last_updated = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify(success=True, message="Order submitted successfully")
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message="Failed to submit order"), 500

@app.route('/api/table_status/<int:table_id>')
def table_status(table_id):
    if not check_guest_access():
        return jsonify(error="Access denied"), 403
    
    table = Table.query.get_or_404(table_id)
    
    # セッションのテーブル名と一致するかチェック
    if session.get('table_name') != table.name:
        return jsonify(error="Invalid table access"), 403
    
    orders = table.orders.order_by(Order.timestamp.desc()).all()
    total_price = sum(order.item_price * order.quantity for order in orders)
    
    orders_data = []
    for o in orders:
        orders_data.append({
            'id': o.id,
            'name': o.item_name,
            'quantity': o.quantity,
            'status': o.status,
            'notes': o.notes or '',
            'price': o.item_price
        })
    
    return jsonify(orders=orders_data, total_price=total_price, table_status=table.status)

# --- 管理者用API ---
@app.route('/api/order/serve', methods=['POST'])
@login_required
def serve_order():
    data = request.get_json()
    order_id = data.get('order_id')
    order = Order.query.get(order_id)
    if order:
        order.status = 'served'
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/api/order/update_status', methods=['POST'])
@login_required
def update_order_status():
    data = request.get_json()
    order_id = data.get('order_id')
    new_status = data.get('status')
    
    if new_status not in ['pending', 'preparing', 'ready', 'served']:
        return jsonify(success=False, message="Invalid status"), 400
    
    order = Order.query.get(order_id)
    if order:
        order.status = new_status
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/api/kitchen_status')
@login_required
def kitchen_status():
    pending_orders = db.session.query(Order, Table).join(Table).filter(
        Order.status.in_(['pending', 'preparing'])
    ).order_by(Order.timestamp).all()
    
    orders_data = []
    for order, table in pending_orders:
        orders_data.append({
            'id': order.id,
            'item_name': order.item_name,
            'quantity': order.quantity,
            'timestamp': order.timestamp.strftime('%H:%M:%S'),
            'table_id': table.id,
            'table_name': table.name,
            'status': order.status,
            'notes': order.notes or ''
        })
    return jsonify(pending_orders=orders_data)

# --- 案内管理API ---
@app.route('/api/guidance/create', methods=['POST'])
@login_required
def create_guidance():
    data = request.get_json()
    table_name = data.get('table_name')
    guest_count = data.get('guest_count')
    
    if not table_name or not guest_count:
        return jsonify(success=False, message="Missing required fields"), 400
    
    # 有効期限を30分後に設定
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    
    # セッショントークンを生成
    session_token = str(uuid.uuid4())
    
    try:
        guest_session = GuestSession(
            session_token=session_token,
            table_name=table_name,
            guest_count=guest_count,
            expires_at=expires_at,
            created_by=current_user.id
        )
        db.session.add(guest_session)
        db.session.commit()
        
        # QRコード用のURLを生成
        qr_url = url_for('direct_menu_access', token=session_token, _external=True)
        
        return jsonify(
            success=True,
            session_id=guest_session.id,
            qr_url=qr_url,
            expires_at=expires_at.isoformat()
        )
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message="Failed to create guidance session"), 500

@app.route('/api/guidance/complete/<int:session_id>', methods=['POST'])
@login_required
def complete_guidance(session_id):
    guest_session = GuestSession.query.get_or_404(session_id)
    
    try:
        # テーブルを作成または更新
        table = Table.query.filter_by(name=guest_session.table_name).first()
        if not table:
            table = Table(
                name=guest_session.table_name,
                status='occupied',
                current_guests=guest_session.guest_count
            )
            db.session.add(table)
        else:
            table.status = 'occupied'
            table.current_guests = guest_session.guest_count
            table.last_updated = datetime.datetime.utcnow()
        
        # 案内セッションのステータスを更新
        guest_session.status = 'seated'
        
        db.session.commit()
        
        return jsonify(success=True, table_id=table.id)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message="Failed to complete guidance"), 500

# --- 管理者用ページ ---
@app.route('/admin_login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('kitchen'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # IP制限チェック（設定されている場合）
            allowed_ips = user.get_allowed_ips()
            if allowed_ips and request.remote_addr not in allowed_ips:
                log_access('unauthorized_admin_login', is_suspicious=True)
                flash('このIPアドレスからのアクセスは許可されていません。', 'danger')
                return render_template('login.html')
            
            login_user(user)
            log_access('admin_login_success')
            return redirect(url_for('kitchen'))
        else:
            log_access('admin_login_failed', is_suspicious=True)
            flash('ユーザー名またはパスワードが違います。', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_access('admin_logout')
    logout_user()
    return redirect(url_for('login'))

@app.route('/kitchen')
@login_required
def kitchen():
    return render_template('kitchen.html')

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    """案内管理ページ"""
    active_sessions = GuestSession.query.filter(
        GuestSession.status == 'waiting',
        GuestSession.expires_at > datetime.datetime.utcnow()
    ).order_by(GuestSession.qr_generated_at.desc()).all()
    
    return render_template('admin_guidance.html', active_sessions=active_sessions)

@app.route('/admin/tables')
@login_required
def admin_tables():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_tables.html', tables=tables)

@app.route('/admin/tables/add', methods=['POST'])
@login_required
def add_table():
    table_name = request.form.get('name')
    capacity = request.form.get('capacity', 4, type=int)
    
    if table_name and not Table.query.filter_by(name=table_name).first():
        new_table = Table(name=table_name, capacity=capacity)
        db.session.add(new_table)
        db.session.commit()
        flash(f'テーブル「{table_name}」を追加しました。', 'success')
    else:
        flash(f'テーブル「{table_name}」は既に存在するか、名前が空です。', 'danger')
    return redirect(url_for('admin_tables'))

@app.route('/admin/tables/update_status/<int:table_id>', methods=['POST'])
@login_required
def update_table_status(table_id):
    table = Table.query.get_or_404(table_id)
    new_status = request.form.get('status')
    
    if new_status in ['available', 'occupied', 'cleaning', 'reserved']:
        table.status = new_status
        table.last_updated = datetime.datetime.utcnow()
        db.session.commit()
        flash(f'テーブル「{table.name}」のステータスを更新しました。', 'success')
    
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
        category=request.form.get('category'),
        description=request.form.get('description', ''),
        image_url=request.form.get('image_url', '')
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
    # テーブルステータスをリセット
    table.status = 'available'
    table.current_guests = 0
    db.session.commit()
    flash(f'テーブル「{table.name}」の注文履歴を削除しました。', 'success')
    return redirect(url_for('admin_history'))

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    """簡単な統計情報"""
    today = datetime.date.today()
    
    # 今日の注文数
    today_orders = Order.query.filter(
        Order.timestamp >= datetime.datetime.combine(today, datetime.time.min)
    ).count()
    
    # 今日の売上
    today_revenue = db.session.query(db.func.sum(Order.item_price * Order.quantity)).filter(
        Order.timestamp >= datetime.datetime.combine(today, datetime.time.min)
    ).scalar() or 0
    
    # 人気メニュー
    popular_items = db.session.query(
        Order.item_name,
        db.func.sum(Order.quantity).label('total_quantity')
    ).group_by(Order.item_name).order_by(db.desc('total_quantity')).limit(5).all()
    
    return render_template('admin_analytics.html',
                         today_orders=today_orders,
                         today_revenue=today_revenue,
                         popular_items=popular_items)

@app.route('/admin/security')
@login_required
def admin_security():
    """セキュリティログ確認"""
    recent_logs = AccessLog.query.filter_by(is_suspicious=True).order_by(
        AccessLog.timestamp.desc()
    ).limit(50).all()
    
    return render_template('admin_security.html', recent_logs=recent_logs)

# --- エラーページ ---
@app.errorhandler(403)
def forbidden(error):
    return render_template('access_denied.html'), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('not_found.html'), 404

# --- データベース初期化とクリーンアップ ---
def cleanup_expired_sessions():
    """期限切れのセッションを削除"""
    try:
        expired_sessions = GuestSession.query.filter(
            GuestSession.expires_at < datetime.datetime.utcnow()
        ).all()
        
        for session in expired_sessions:
            session.status = 'expired'
        
        db.session.commit()
    except:
        pass

# --- アプリ起動時にデータベースを自動作成 ---
with app.app_context():
    # まず、全てのテーブルを作成する
    db.create_all()
    print("Database tables created or already exist.")

    # 次に、管理者ユーザーの存在を確認して作成する
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('password123')
        # 開発環境用のIP許可リスト（本番では削除推奨）
        admin_user.set_allowed_ips(['127.0.0.1', '::1'])
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created.")
    
    # 期限切れセッションのクリーンアップ
    cleanup_expired_sessions()

# --- アプリケーションの実行 ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)