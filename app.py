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
from math import ceil
from flask_migrate import Migrate

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)

# SECRET_KEYの強化
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# データベース設定 (Render PostgreSQL対応)
db_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/test.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_recycle': 3600, 'pool_pre_ping': True}

# セッション設定
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# 拡張機能の初期化
db = SQLAlchemy(app)
migrate = Migrate(app, db)
JST = pytz.timezone('Asia/Tokyo')

# --- ログイン機能の設定 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "このページにアクセスするにはログインが必要です。"
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.path.startswith('/api/'):
        return jsonify(success=False, message='Authentication required'), 401
    return redirect(url_for('login'))

# --- データベースモデル定義 ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    items = db.relationship('MenuItem', backref='category_ref', lazy='dynamic', cascade="all, delete-orphan")

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    popularity_count = db.Column(db.Integer, default=0, nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    orders = db.relationship('Order', backref='menu_item', lazy='dynamic')

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='available', nullable=False)
    active_qr_token = db.Column(db.String(100), unique=True, nullable=True)
    qr_token_expiry = db.Column(db.DateTime(timezone=True), nullable=True)
    persistent_session_id = db.Column(db.String(100), nullable=True)
    last_accessed = db.Column(db.DateTime(timezone=True), nullable=True)
    orders = db.relationship('Order', backref='table', lazy='dynamic')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=True) # 削除されても履歴は残す
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(JST))
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    persistent_session_id = db.Column(db.String(100), nullable=True)
    individual_session_id = db.Column(db.String(100), nullable=True)

class TempQRToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    table_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(JST))
    used = db.Column(db.Boolean, default=False)
    def is_valid(self):
        return not self.used and (self.created_at + datetime.timedelta(minutes=30)) > datetime.datetime.now(JST)

# --- ユーティリティ ---
@app.context_processor
def inject_globals():
    return dict(JST=JST)

def init_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('password123')
            db.session.add(admin_user)
            print("✅ Admin user created: admin / password123")
        db.session.commit()

# --- メインルート ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/qr/<token>')
def qr_auth(token):
    table = None
    temp_token = TempQRToken.query.filter_by(token=token).first()
    
    if temp_token and temp_token.is_valid():
        table = Table.query.filter_by(name=temp_token.table_name).first()
        if not table:
            table = Table(name=temp_token.table_name, persistent_session_id=secrets.token_hex(16))
            db.session.add(table)
        temp_token.used = True
    else:
        table = Table.query.filter_by(active_qr_token=token).first()
        if not table or (table.qr_token_expiry and table.qr_token_expiry < datetime.datetime.now(JST)):
            flash('QRコードが無効か期限切れです。', 'danger')
            return redirect(url_for('index'))

    if not table.persistent_session_id:
        table.persistent_session_id = secrets.token_hex(16)
    
    session['table_id'] = table.id
    session['persistent_session_id'] = table.persistent_session_id
    session['individual_session_id'] = secrets.token_hex(8)
    table.status = 'occupied'
    table.last_accessed = datetime.datetime.now(JST)
    db.session.commit()
    return redirect(url_for('table_menu', table_id=table.id))

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    if session.get('table_id') != table_id and not (current_user.is_authenticated):
        abort(403)
    table = db.session.get(Table, table_id) or abort(404)
    
    categories = Category.query.order_by(Category.sort_order).all()
    menu = [{'category_name': c.name, 'item_list': c.items.filter_by(active=True).order_by(MenuItem.sort_order).all()} for c in categories]
    
    return render_template('table_menu.html', table=table, categorized_menu=menu)

# --- 管理者ルート ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password', '')):
            login_user(user, remember=True)
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('ユーザー名またはパスワードが違います。', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('ログアウトしました。', 'success')
    return redirect(url_for('login'))

@app.route('/kitchen')
@login_required
def kitchen():
    today = datetime.datetime.now(JST).date()
    stats = {
        'pending_orders': Order.query.filter_by(status='pending').count(),
        'preparing_orders': Order.query.filter_by(status='preparing').count(),
        'ready_orders': Order.query.filter_by(status='ready').count(),
        'total_orders': Order.query.filter(func.date(Order.timestamp) == today).count()
    }
    return render_template('kitchen.html', stats=stats)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin/menu')
@login_required
def admin_menu():
    categories = Category.query.order_by(Category.sort_order).all()
    categorized_items = [{'category_obj': c, 'item_list': c.items.order_by(MenuItem.sort_order).all()} for c in categories]
    return render_template('admin_menu.html', categorized_items=categorized_items)

@app.route('/admin/tables')
@login_required
def admin_tables():
    return render_template('admin_tables.html', tables=Table.query.order_by(Table.name).all())

@app.route('/admin/history')
@login_required
def admin_history():
    return render_template('admin_history.html', tables=Table.query.order_by(Table.name).all())

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    return render_template('admin_guidance.html')

# --- API エンドポイント ---
@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    data = request.json
    table_id = session.get('table_id')
    items = data.get('items')

    if not all([table_id, items]):
        return jsonify(success=False, message="セッション情報または注文内容が無効です。"), 400

    for item_id_str, item_data in items.items():
        item_id = int(item_id_str)
        quantity = item_data.get('quantity', 0)
        menu_item = db.session.get(MenuItem, item_id)
        
        if menu_item and quantity > 0:
            for _ in range(quantity):
                order = Order(
                    menu_item_id=menu_item.id, item_name=menu_item.name, item_price=menu_item.price,
                    table_id=table_id, persistent_session_id=session.get('persistent_session_id'),
                    individual_session_id=session.get('individual_session_id')
                )
                db.session.add(order)
            menu_item.popularity_count += quantity
    
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/kitchen/orders')
@login_required
def api_kitchen_orders():
    orders = db.session.query(Order, Table.name).join(Table).filter(Order.status.in_(['pending', 'preparing'])).order_by(Order.timestamp.asc()).all()
    output = [{'id': o.id, 'table_name': table_name, 'item_name': o.item_name, 'status': o.status, 'timestamp': o.timestamp.isoformat()} for o, table_name in orders]
    return jsonify(success=True, orders=output)

@app.route('/api/kitchen/orders/<int:order_id>/status', methods=['PUT'])
@login_required
def update_order_status(order_id):
    order = db.session.get(Order, order_id) or abort(404)
    new_status = request.json.get('status')
    if new_status in ['preparing', 'served']:
        order.status = new_status
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False, message="無効なステータスです。"), 400

@app.route('/api/tables/<int:table_id>', methods=['DELETE'])
@login_required
def api_delete_table(table_id):
    table = db.session.get(Table, table_id) or abort(404)
    if table.orders.first():
        return jsonify(success=False, message=f"テーブル '{table.name}' には注文履歴があるため削除できません。"), 400
    db.session.delete(table)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/menu/add', methods=['POST'])
@login_required
def api_add_menu_item():
    data = request.json
    if not all(k in data for k in ['name', 'price', 'category']):
        return jsonify(success=False, message='データが不足しています。'), 400
    
    category = Category.query.filter_by(name=data['category']).first()
    if not category:
        category = Category(name=data['category'], sort_order=Category.query.count())
        db.session.add(category)
        db.session.flush()

    item = MenuItem(name=data['name'], price=int(data['price']), category_id=category.id, sort_order=category.items.count())
    db.session.add(item)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/menu/<int:item_id>', methods=['DELETE'])
@login_required
def api_delete_menu_item(item_id):
    item = db.session.get(MenuItem, item_id) or abort(404)
    if item.orders.first():
        item.active = False
        message = f"メニュー '{item.name}' は注文履歴があるため非表示にしました。"
    else:
        db.session.delete(item)
        message = f"メニュー '{item.name}' を完全に削除しました。"
    db.session.commit()
    return jsonify(success=True, message=message)

@app.route('/api/category/<int:category_id>', methods=['DELETE'])
@login_required
def api_delete_category(category_id):
    category = db.session.get(Category, category_id) or abort(404)
    if db.session.query(Order).join(MenuItem).filter(MenuItem.category_id == category_id).first():
        return jsonify(success=False, message=f"カテゴリ '{category.name}' 内のメニューに注文履歴があるため削除できません。"), 400
    db.session.delete(category)
    db.session.commit()
    return jsonify(success=True, message=f"カテゴリ '{category.name}' を削除しました。")

@app.route('/api/dashboard/summary')
@login_required
def api_dashboard_summary():
    today_start = datetime.datetime.combine(datetime.date.today(), datetime.time.min, tzinfo=JST)
    sales_query = db.session.query(func.sum(Order.item_price), func.count(Order.id)).filter(Order.timestamp >= today_start, Order.status != 'cancelled')
    today_sales, today_orders = sales_query.one()
    today_sales = today_sales or 0
    today_orders = today_orders or 0
    avg_spend = (today_sales / today_orders) if today_orders > 0 else 0
    return jsonify(
        today_sales=f"¥{today_sales:,}",
        today_orders=today_orders,
        avg_spend=f"¥{avg_spend:,.0f}",
        occupied_tables=Table.query.filter_by(status='occupied').count(),
        total_tables=Table.query.count(),
        popular_items=[{'name': i.name, 'count': i.popularity_count} for i in MenuItem.query.order_by(MenuItem.popularity_count.desc()).limit(5).all()]
    )

# ... 他のAPIルートも同様に簡素化・堅牢化 ...

# --- エラーハンドラ ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f"Server Error: {error}")
    return render_template('500.html'), 500

# --- CLIコマンドとアプリ実行 ---
@app.cli.command("init-db")
def init_db_command():
    """データベースを初期化し、管理者ユーザーを作成します。"""
    init_database()

if __name__ == '__main__':
    with app.app_context():
        init_database()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
else: # Gunicorn for production
    with app.app_context():
        init_database()

