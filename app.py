import os
import datetime
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, desc, and_
import pytz
from collections import defaultdict

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

db_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/test.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)

if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)

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
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

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
    active_qr_token = db.Column(db.String(100), unique=True, nullable=True)
    qr_token_expiry = db.Column(db.DateTime(timezone=True), nullable=True)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending -> served
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(JST))
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    session_id = db.Column(db.String(100))

class TempQRToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    table_name = db.Column(db.String(100))
    guest_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(JST))
    used = db.Column(db.Boolean, default=False)
    def is_valid(self):
        if self.used: return False
        expiry = self.created_at + datetime.timedelta(minutes=30)
        return datetime.datetime.now(JST) < expiry

# --- ルートとロジック ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/qr/<token>')
def qr_auth(token):
    # 案内管理で発行された一時トークンを優先して探す
    temp_token = TempQRToken.query.filter_by(token=token).first()
    if temp_token and temp_token.is_valid():
        table = Table.query.filter_by(name=temp_token.table_name).first()
        if not table:
            table = Table(name=temp_token.table_name)
            db.session.add(table)
            # データベースのセッションをフラッシュして、新しいテーブルのIDを確定させる
            db.session.flush()

        # これで table.id は確実にNoneではなくなる
        session['table_id'] = table.id
        session['session_id'] = secrets.token_hex(16)
        
        table.status = 'occupied'
        temp_token.used = True
        
        # 関連する変更をすべてコミット
        db.session.commit()
        
        return redirect(url_for('table_menu', table_id=table.id))

    # 次に、卓管理で発行された固定トークンを探す
    table = Table.query.filter_by(active_qr_token=token).first()
    if table and (not table.qr_token_expiry or table.qr_token_expiry > datetime.datetime.now(JST)):
        session['session_id'] = secrets.token_hex(16)
        session['table_id'] = table.id
        table.status = 'occupied'
        db.session.commit()
        return redirect(url_for('table_menu', table_id=table.id))

    flash('QRコードが無効か期限切れです。', 'danger')
    return redirect(url_for('index'))

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    if not session.get('table_id') == table_id and not (current_user and current_user.is_authenticated):
        abort(403)
    table = db.session.get(Table, table_id)
    if not table: abort(404)
    menu_items = MenuItem.query.filter_by(active=True).order_by(MenuItem.category).all()
    categorized_menu = defaultdict(list)
    for item in menu_items:
        categorized_menu[item.category].append(item)
    return render_template('table_menu.html', table=table, categorized_menu=categorized_menu)

# --- 管理者ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        flash('ユーザー名またはパスワードが違います。', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
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
    return render_template('admin_menu.html', menu_items=MenuItem.query.order_by(MenuItem.category, MenuItem.name).all())

@app.route('/admin/tables')
@login_required
def admin_tables():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_tables.html', tables=tables)

@app.route('/admin/history')
@login_required
def admin_history():
    return render_template('admin_history.html', tables=Table.query.order_by(Table.name).all())

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    return render_template('admin_guidance.html')

# --- APIエンドポイント ---

# Customer APIs
@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    data = request.json
    table_id = session.get('table_id')
    session_id = session.get('session_id')
    items = data.get('items')

    if not table_id or not items or not session_id:
        return jsonify(success=False, message="セッション情報が無効です。"), 400

    for item_id, item_data in items.items():
        menu_item = db.session.get(MenuItem, int(item_id))
        if menu_item and item_data.get('quantity', 0) > 0:
            for _ in range(item_data['quantity']):
                order = Order(item_name=menu_item.name, item_price=menu_item.price, table_id=table_id, session_id=session_id)
                db.session.add(order)
            menu_item.popularity_count += item_data['quantity']
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/customer/orders')
def api_customer_orders():
    if 'session_id' in session:
        orders = Order.query.filter_by(session_id=session['session_id']).order_by(Order.timestamp.asc()).all()
        order_list = [{'name': o.item_name, 'price': o.item_price, 'status': o.status} for o in orders]
        total = sum(o.item_price for o in orders)
        return jsonify(success=True, orders=order_list, total=total)
    return jsonify(success=False, message="注文履歴がありません。")

# Kitchen APIs
@app.route('/api/kitchen/orders')
@login_required
def api_kitchen_orders():
    orders_query = Order.query.filter_by(status='pending').order_by(Order.timestamp.asc()).all()
    
    orders_by_session = defaultdict(list)
    for o in orders_query:
        orders_by_session[o.session_id].append(o)

    output = []
    for session_id, orders in orders_by_session.items():
        if not orders: continue
        
        item_counts = defaultdict(int)
        for item in orders:
            item_counts[item.item_name] += 1
        
        output.append({
            'session_id': session_id,
            'table_name': orders[0].table.name,
            'timestamp': orders[0].timestamp.isoformat(),
            'items': [{'name': name, 'quantity': qty} for name, qty in item_counts.items()]
        })
    return jsonify(success=True, orders=output)

@app.route('/api/order/complete/<session_id>', methods=['POST'])
@login_required
def api_complete_order(session_id):
    orders = Order.query.filter_by(session_id=session_id, status='pending').all()
    if not orders:
        return jsonify(success=False, message="対象の注文が見つかりません。"), 404
    for order in orders:
        order.status = 'served'
    db.session.commit()
    return jsonify(success=True)

# Guidance APIs
@app.route('/api/guidance/generate', methods=['POST'])
@login_required
def api_generate_guidance_qr():
    data = request.json
    table_name = data.get('table_name')
    if not table_name:
        return jsonify(success=False, message="テーブル名を入力してください。"), 400
    
    token = secrets.token_urlsafe(16)
    new_qr = TempQRToken(
        token=token,
        table_name=table_name,
        guest_count=int(data.get('guest_count', 1))
    )
    db.session.add(new_qr)
    db.session.commit()
    
    return jsonify(success=True, token=token, table_name=table_name)

# Table Management APIs
@app.route('/api/qr/generate/<int:table_id>', methods=['POST'])
@login_required
def api_generate_table_qr(table_id):
    table = db.session.get(Table, table_id)
    if not table:
        return jsonify(success=False, message="Table not found"), 404
    
    table.active_qr_token = secrets.token_urlsafe(16)
    table.qr_token_expiry = datetime.datetime.now(JST) + datetime.timedelta(hours=8)
    db.session.commit()
    
    return jsonify(
        success=True, 
        token=table.active_qr_token, 
        expiry=table.qr_token_expiry.isoformat()
    )

@app.route('/api/tables', methods=['POST'])
@login_required
def api_add_table():
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify(success=False, message='Table name is required'), 400
    if Table.query.filter_by(name=name).first():
        return jsonify(success=False, message='Table name already exists'), 400
    
    new_table = Table(name=name)
    db.session.add(new_table)
    db.session.commit()
    return jsonify(success=True, id=new_table.id, name=new_table.name)

@app.route('/api/tables/<int:table_id>', methods=['DELETE'])
@login_required
def api_delete_table(table_id):
    table = db.session.get(Table, table_id)
    if not table:
        return jsonify(success=False, message="Table not found"), 404
    db.session.delete(table)
    db.session.commit()
    return jsonify(success=True)

# Menu Management APIs
@app.route('/api/menu/add', methods=['POST'])
@login_required
def api_add_menu_item():
    data = request.json
    name = data.get('name')
    price = data.get('price')
    category = data.get('category')
    if not all([name, price, category]):
        return jsonify(success=False, message='Missing data'), 400
    
    item = MenuItem(name=name, price=int(price), category=category)
    db.session.add(item)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/menu/<int:item_id>', methods=['DELETE'])
@login_required
def api_delete_menu_item(item_id):
    item = db.session.get(MenuItem, item_id)
    if not item:
        return jsonify(success=False, message="Item not found"), 404
    db.session.delete(item)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/menu/toggle/<int:item_id>', methods=['POST'])
@login_required
def api_toggle_menu_item_active(item_id):
    item = db.session.get(MenuItem, item_id)
    if not item:
        return jsonify(success=False, message="Item not found"), 404
    item.active = not item.active
    db.session.commit()
    return jsonify(success=True, active=item.active)


# Dashboard APIs
@app.route('/api/stats/dashboard')
@login_required
def api_stats_dashboard():
    today = datetime.datetime.now(JST).date()
    start_of_day = datetime.datetime.combine(today, datetime.time.min).astimezone(JST)
    
    today_sales = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp >= start_of_day).scalar() or 0
    order_count = db.session.query(func.count(Order.id)).filter(Order.timestamp >= start_of_day).scalar() or 0
    
    table_stats = db.session.query(Table.status, func.count(Table.id)).group_by(Table.status).all()
    table_stats_dict = {status: count for status, count in table_stats}

    popular_items = db.session.query(MenuItem.name, MenuItem.popularity_count).order_by(MenuItem.popularity_count.desc()).limit(5).all()

    return jsonify(
        today_sales=today_sales,
        order_count=order_count,
        table_stats={'available': table_stats_dict.get('available', 0), 'occupied': table_stats_dict.get('occupied', 0)},
        popular_items=[{'name': name, 'count': count} for name, count in popular_items]
    )

@app.route('/api/dashboard/sales')
@login_required
def api_dashboard_sales():
    period = request.args.get('period', 'daily')
    today = datetime.datetime.now(JST).date()
    
    if period == 'monthly':
        start_date = today.replace(day=1) - datetime.timedelta(days=365) # Last 12 months
        start_date = start_date.replace(day=1)
        
        sales_data = db.session.query(
            func.date_trunc('month', Order.timestamp),
            func.sum(Order.item_price)
        ).filter(Order.timestamp >= start_date).group_by(func.date_trunc('month', Order.timestamp)).order_by(func.date_trunc('month', Order.timestamp)).all()

        labels = [d.strftime("%Y-%m") for d, _ in sales_data]
        sales = [s for _, s in sales_data]

    else: # daily
        start_date = today - datetime.timedelta(days=29)
        
        sales_data = db.session.query(
            func.cast(Order.timestamp, db.Date),
            func.sum(Order.item_price)
        ).filter(func.cast(Order.timestamp, db.Date) >= start_date).group_by(func.cast(Order.timestamp, db.Date)).order_by(func.cast(Order.timestamp, db.Date)).all()
        
        date_to_sales = {d.strftime("%Y-%m-%d"): s for d, s in sales_data}
        labels = [(start_date + datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(30)]
        sales = [date_to_sales.get(label, 0) for label in labels]

    return jsonify(labels=labels, sales=sales)


# --- データベース初期化コマンド ---
@app.cli.command("init-db")
def init_db_command():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin_user = User(username='admin')
        admin_user.set_password('password123')
        db.session.add(admin_user)
        # Add sample data
        db.session.add_all([Table(name=f'{i}番テーブル') for i in range(1, 6)])
        
        menu_items_data = [
            {'name': 'ブレンドコーヒー', 'price': 500, 'category': 'ドリンク'},
            {'name': 'カフェラテ', 'price': 600, 'category': 'ドリンク'},
            {'name': 'チーズケーキ', 'price': 700, 'category': 'デザート'},
            {'name': 'ナポリタン', 'price': 1200, 'category': 'フード'},
        ]
        for item_data in menu_items_data:
            db.session.add(MenuItem(**item_data))

        db.session.commit()
        print("データベースが初期化され、サンプルデータが追加されました。")
        print("管理者アカウント: admin / password123")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)