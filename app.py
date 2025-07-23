import os
import datetime
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, desc
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
    qr_token_expiry = db.Column(db.DateTime, nullable=True)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(JST))
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    session_id = db.Column(db.String(100))

# --- ルートとロジック ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/qr/<token>')
def qr_auth(token):
    table = Table.query.filter_by(active_qr_token=token).first()
    if not table or (table.qr_token_expiry and table.qr_token_expiry < datetime.datetime.now(JST)):
        flash('QRコードが無効か期限切れです。', 'danger')
        return redirect(url_for('index'))
    
    session['qr_token'] = token
    session['table_id'] = table.id
    table.status = 'occupied'
    db.session.commit()
    return redirect(url_for('table_menu', table_id=table.id))

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    is_admin = current_user.is_authenticated
    if not is_admin and session.get('table_id') != table_id:
        abort(403)
    table = db.session.get(Table, table_id)
    if not table: abort(404)
    menu_items = MenuItem.query.filter_by(active=True).all()
    categorized_menu = {}
    for item in menu_items:
        categorized_menu.setdefault(item.category, []).append(item)
    return render_template('table_menu.html', table=table, categorized_menu=categorized_menu)

# --- 管理者ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=('remember_me' in request.form))
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
    stats = {
        "pending_orders": Order.query.filter_by(status='pending').count(),
        "preparing_orders": Order.query.filter_by(status='cooking').count(),
        "ready_orders": Order.query.filter_by(status='served').count(),
        "total_orders": Order.query.filter(Order.timestamp >= datetime.datetime.now(JST).replace(hour=0, minute=0, second=0)).count()
    }
    return render_template('kitchen.html', stats=stats)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin/menu')
@login_required
def admin_menu():
    menu_items = MenuItem.query.order_by(MenuItem.category, MenuItem.name).all()
    return render_template('admin_menu.html', menu_items=menu_items)

@app.route('/admin/tables')
@login_required
def admin_tables():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_tables.html', tables=tables)

@app.route('/admin/history')
@login_required
def admin_history():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_history.html', tables=tables)

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    return render_template('admin_guidance.html')

# --- APIエンドポイント ---
@app.route('/api/tables', methods=['POST'])
@login_required
def api_add_table():
    name = request.json.get('name')
    if name and not Table.query.filter_by(name=name).first():
        new_table = Table(name=name)
        db.session.add(new_table)
        db.session.commit()
        return jsonify(success=True, table={'id': new_table.id, 'name': new_table.name, 'status': new_table.status, 'active_qr_token': None, 'qr_token_expiry': None})
    return jsonify(success=False, message='テーブル名が無効か、既に存在します。'), 400

@app.route('/api/tables/<int:table_id>', methods=['DELETE'])
@login_required
def api_delete_table(table_id):
    table = db.session.get(Table, table_id)
    if table:
        Order.query.filter_by(table_id=table.id).delete()
        db.session.delete(table)
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False, message='テーブルが見つかりません。'), 404

@app.route('/api/qr/generate/<int:table_id>', methods=['POST'])
@login_required
def api_generate_qr(table_id):
    table = db.session.get(Table, table_id)
    if not table:
        return jsonify(success=False, message='テーブルが見つかりません。'), 404
    
    table.active_qr_token = secrets.token_urlsafe(16)
    table.qr_token_expiry = datetime.datetime.now(JST) + datetime.timedelta(hours=3)
    db.session.commit()
    
    return jsonify(
        success=True,
        token=table.active_qr_token,
        expiry=table.qr_token_expiry.strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    data = request.get_json()
    table = db.session.get(Table, data.get('table_id'))
    if not table: return jsonify(success=False, message="テーブル情報がありません。"), 400
    
    session_id = secrets.token_hex(16)
    
    for item_id, item_data in data.get('items', {}).items():
        menu_item = db.session.get(MenuItem, int(item_id))
        if menu_item:
            menu_item.popularity_count += item_data['quantity']
            for _ in range(item_data['quantity']):
                db.session.add(Order(item_name=item_data['name'], item_price=item_data['price'], table_id=table.id, session_id=session_id))
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/kitchen/orders')
@login_required
def api_kitchen_orders():
    active_orders_query = Order.query.filter(Order.status.in_(['pending', 'cooking', 'served'])).order_by(Order.timestamp).all()
    orders_by_session = defaultdict(list)
    for order in active_orders_query:
        orders_by_session[order.session_id].append(order)

    orders_data = []
    for session_id, items in orders_by_session.items():
        if not items: continue
        aggregated_items = defaultdict(lambda: {'quantity': 0, 'notes': ''})
        for item in items: aggregated_items[item.item_name]['quantity'] += 1
        
        statuses = {item.status for item in items}
        status_priority = ['pending', 'cooking', 'served']
        group_status = 'served'
        for s in status_priority:
            if s in statuses:
                group_status = s
                break
        
        status_map_js = {'pending': 'pending', 'cooking': 'preparing', 'served': 'ready'}

        orders_data.append({
            'id': session_id,
            'table_number': items[0].table.name,
            'created_at': items[0].timestamp.isoformat(),
            'status': status_map_js.get(group_status, 'pending'),
            'items': [{'name': name, 'quantity': data['quantity'], 'notes': data['notes']} for name, data in aggregated_items.items()]
        })

    stats = {
        "pending_orders": Order.query.filter_by(status='pending').count(),
        "preparing_orders": Order.query.filter_by(status='cooking').count(),
        "ready_orders": Order.query.filter_by(status='served').count(),
        "total_orders": Order.query.filter(Order.timestamp >= datetime.datetime.now(JST).replace(hour=0, minute=0, second=0)).count()
    }
    return jsonify(success=True, orders=orders_data, stats=stats)

# --- データベース初期化コマンド ---
@app.cli.command("init-db")
def init_db_command():
    """データベースをクリアし、初期データを投入します。"""
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin_user = User(username='admin')
        admin_user.set_password('password123')
        db.session.add(admin_user)
        db.session.add_all([Table(name=f'{i}番テーブル') for i in range(1, 6)])
        db.session.commit()
        print("データベースが初期化されました。")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
