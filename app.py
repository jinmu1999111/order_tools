import os
import datetime
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, desc, and_, text
import pytz
from collections import defaultdict
from math import ceil
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)

# SECRET_KEYの強化
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for Flask application. Please set it in the environment variables.")
app.secret_key = SECRET_KEY

# データベース設定の改善
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
if not db_url:
    db_url = 'sqlite:///instance/test.db'

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 280,   # Renderのタイムアウト(300秒)より短く設定
    'pool_pre_ping': True, # 接続が有効か事前に確認する
    'pool_size': 5,        # 保持する接続の数
    'max_overflow': 2      # 一時的に許可する追加の接続数
}
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)

# セッションの改善
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
os.makedirs(instance_path, exist_ok=True)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
JST = pytz.timezone('Asia/Tokyo')

# --- テンプレートで使用するグローバル変数を設定 ---
@app.context_processor
def inject_globals():
    return dict(JST=JST)

# --- ログイン機能の設定 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "このページにアクセスするにはログインが必要です。"
login_manager.session_protection = "strong"  # セッション保護を強化

@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.path.startswith('/api/'):
        return jsonify(success=False, message='Authentication required'), 401
    return redirect(url_for('login'))

# --- データベースモデルの定義 ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=True)
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
    description = db.Column(db.Text, nullable=True)  # 商品説明
    active = db.Column(db.Boolean, default=True)
    popularity_count = db.Column(db.Integer, default=0)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='available')
    active_qr_token = db.Column(db.String(100), unique=True, nullable=True)
    # QRコード固有のセッションID（テーブル単位で永続化）
    persistent_session_id = db.Column(db.String(100), nullable=True)
    # 最後にアクセスされた時刻
    last_accessed = db.Column(db.DateTime(timezone=True), nullable=True)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(JST))
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    # テーブルの永続セッションIDを参照
    persistent_session_id = db.Column(db.String(100), nullable=True)
    # 個別セッション（同じテーブルでも複数グループが注文する場合用）
    individual_session_id = db.Column(db.String(100), nullable=True)

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

# --- データベース初期化関数 ---
def init_database():
    """アプリケーション起動時にデータベースを初期化"""
    try:
        with app.app_context():
            db.create_all()
            
            # 既存テーブルに新しいカラムを追加（マイグレーション用）
            try:
                db.session.execute(text('SELECT description FROM menu_item LIMIT 1'))
            except Exception:
                # description カラムが存在しない場合は追加
                print("Adding new column to menu_item table...")
                try:
                    db.session.execute(text('ALTER TABLE menu_item ADD COLUMN description TEXT'))
                    db.session.commit()
                    print("New column added to menu_item table.")
                except Exception as e:
                    print(f"Column addition error (may already exist): {e}")
                    db.session.rollback()
            
            # 管理者アカウントの作成
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin')
                admin_user.set_password('password123')
                db.session.add(admin_user)
                print("管理者アカウントを作成しました: admin / password123")
            
            # サンプルテーブルの作成（永続セッションID付き）
            if Table.query.count() == 0:
                for i in range(1, 6):
                    table = Table(name=f'{i}番テーブル')
                    table.active_qr_token = secrets.token_urlsafe(16)
                    table.persistent_session_id = secrets.token_hex(16)
                    db.session.add(table)
                print("サンプルテーブルを作成しました。")
            
            # 既存テーブルに永続セッションIDを追加（マイグレーション用）
            existing_tables = Table.query.filter_by(persistent_session_id=None).all()
            for table in existing_tables:
                table.persistent_session_id = secrets.token_hex(16)
                if not table.active_qr_token:
                    table.active_qr_token = secrets.token_urlsafe(16)
                print(f"テーブル '{table.name}' に永続セッションIDを追加しました。")
            
            # サンプルメニューデータの追加（開発用）
            if MenuItem.query.count() == 0:
                print("サンプルメニューを作成中...")
                # サンプルカテゴリとメニューを作成
                appetizer_cat = Category(name='前菜', sort_order=0)
                main_cat = Category(name='メイン', sort_order=1)
                dessert_cat = Category(name='デザート', sort_order=2)
                drink_cat = Category(name='ドリンク', sort_order=3)
                
                db.session.add_all([appetizer_cat, main_cat, dessert_cat, drink_cat])
                db.session.flush()
                
                sample_items = [
                    MenuItem(name='シーザーサラダ', price=800, description='新鮮なロメインレタスとパルメザンチーズの定番サラダ', category_id=appetizer_cat.id, sort_order=0),
                    MenuItem(name='エビとアボカドのカクテル', price=1200, description='プリプリのエビと濃厚アボカドの前菜', category_id=appetizer_cat.id, sort_order=1),
                    MenuItem(name='グリルチキン', price=1800, description='ジューシーなグリルチキンとハーブソース', category_id=main_cat.id, sort_order=0),
                    MenuItem(name='ビーフステーキ', price=2800, description='柔らかな牛肉のステーキ、お好みの焼き加減で', category_id=main_cat.id, sort_order=1),
                    MenuItem(name='パスタ ボロネーゼ', price=1600, description='濃厚なミートソースのパスタ', category_id=main_cat.id, sort_order=2),
                    MenuItem(name='ティラミス', price=600, description='イタリア伝統のマスカルポーネデザート', category_id=dessert_cat.id, sort_order=0),
                    MenuItem(name='チョコレートケーキ', price=700, description='濃厚なチョコレートケーキ', category_id=dessert_cat.id, sort_order=1),
                    MenuItem(name='コーヒー', price=400, description='深煎りのブレンドコーヒー', category_id=drink_cat.id, sort_order=0),
                    MenuItem(name='紅茶', price=400, description='芳醇な香りの紅茶', category_id=drink_cat.id, sort_order=1),
                    MenuItem(name='オレンジジュース', price=500, description='新鮮なオレンジの100%ジュース', category_id=drink_cat.id, sort_order=2),
                ]
                
                db.session.add_all(sample_items)
                print("サンプルメニューを作成しました。")
            
            db.session.commit()
            print("データベースの初期化・更新が完了しました。")
    except Exception as e:
        print(f"データベース初期化エラー: {e}")
        db.session.rollback()

# --- ルートとロジック ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    # セッション情報をクリアして、明確にホーム画面を表示
    if 'table_id' in session:
        # 顧客セッションが残っている場合はクリア
        session.clear()
    
    # 管理者がログイン済みの場合はダッシュボードにリダイレクト
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # それ以外はホーム画面を表示
    return render_template('index.html')

@app.route('/clear-session')
def clear_session():
    """セッションクリア用エンドポイント（デバッグ用）"""
    session.clear()
    flash('セッションをクリアしました。', 'success')
    return redirect(url_for('index'))

@app.route('/qr/<token>')
def qr_auth(token):
    try:
        # 一時QRトークンの処理
        temp_token = TempQRToken.query.filter_by(token=token).first()
        if temp_token and temp_token.is_valid():
            table = Table.query.filter_by(name=temp_token.table_name).first()
            if not table:
                table = Table(name=temp_token.table_name)
                table.persistent_session_id = secrets.token_hex(16)
                table.active_qr_token = secrets.token_urlsafe(16)
                db.session.add(table)
                db.session.flush()
            
            if not table.persistent_session_id:
                table.persistent_session_id = secrets.token_hex(16)
            
            # 顧客セッション情報を設定
            session.clear()
            session['table_id'] = table.id
            session['persistent_session_id'] = table.persistent_session_id
            session['individual_session_id'] = secrets.token_hex(8)
            session['is_customer'] = True
            
            table.status = 'occupied'
            table.last_accessed = datetime.datetime.now(JST)
            temp_token.used = True
            db.session.commit()
            
            return redirect(url_for('table_menu', table_id=table.id))
        
        # 通常のテーブルQRトークンの処理
        table = Table.query.filter_by(active_qr_token=token).first()
        if table:
            if not table.persistent_session_id:
                table.persistent_session_id = secrets.token_hex(16)
            
            # 顧客セッション情報を設定
            session.clear()
            session['table_id'] = table.id
            session['persistent_session_id'] = table.persistent_session_id
            session['individual_session_id'] = secrets.token_hex(8)
            session['is_customer'] = True
            
            table.status = 'occupied'
            table.last_accessed = datetime.datetime.now(JST)
            db.session.commit()
            
            return redirect(url_for('table_menu', table_id=table.id))
        
        flash('QRコードが無効か期限切れです。', 'danger')
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"QR認証エラー: {e}")
        flash('QRコードの処理中にエラーが発生しました。', 'danger')
        return redirect(url_for('index'))

def get_menu_data(sort_by='category'):
    if sort_by == 'popularity':
        items = MenuItem.query.filter_by(active=True).order_by(MenuItem.popularity_count.desc()).all()
        return {'item_list': items}
    else:
        sorted_categories = Category.query.order_by(Category.sort_order).all()
        categorized_menu = []
        for category in sorted_categories:
            items = MenuItem.query.filter_by(active=True, category_id=category.id).order_by(MenuItem.sort_order).all()
            if items:
                categorized_menu.append({'category_name': category.name, 'item_list': items})
        return {'categorized_menu': categorized_menu}

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    # 顧客セッションまたは管理者のみアクセス可能
    if not (session.get('table_id') == table_id and session.get('is_customer')) and not current_user.is_authenticated:
        session.clear()
        flash('無効なアクセスです。QRコードから再度アクセスしてください。', 'warning')
        return redirect(url_for('index'))
    
    table = db.session.get(Table, table_id)
    if not table: 
        abort(404)
    
    menu_data = get_menu_data()
    return render_template('table_menu.html', table=table, **menu_data)

@app.route('/table/<int:table_id>/menu_partial')
def table_menu_partial(table_id):
    sort_by = request.args.get('sort_by', 'category')
    menu_data = get_menu_data(sort_by)
    if sort_by == 'popularity':
        return render_template('_menu_popular.html', items=menu_data['item_list'])
    else:
        return render_template('_menu_category.html', categorized_menu=menu_data['categorized_menu'])

# --- 管理者ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。', 'error')
            return render_template('login.html')
        
        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user, remember=True)
                session.permanent = True
                
                # 顧客セッション情報をクリア
                session.pop('is_customer', None)
                session.pop('table_id', None)
                session.pop('persistent_session_id', None)
                session.pop('individual_session_id', None)
                
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                flash('ユーザー名またはパスワードが違います。', 'error')
        except Exception as e:
            print(f"ログインエラー: {e}")
            flash('ログイン処理中にエラーが発生しました。', 'error')
    
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
    today_start = datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    pending_orders = Order.query.filter_by(status='pending').count()
    preparing_orders = Order.query.filter_by(status='preparing').count()
    ready_orders = Order.query.filter_by(status='ready').count()
    total_orders = Order.query.filter(Order.timestamp >= today_start).count()
    stats = {'pending_orders': pending_orders, 'preparing_orders': preparing_orders, 'ready_orders': ready_orders, 'total_orders': total_orders}
    return render_template('kitchen.html', stats=stats)

@app.route('/dashboard')
@login_required
def dashboard():
    today_start = datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    sales_query = db.session.query(func.sum(Order.item_price), func.count(Order.id)).filter(Order.timestamp >= today_start, Order.status != 'cancelled')
    today_sales, today_orders = sales_query.one()
    today_sales = today_sales or 0
    today_orders = today_orders or 0
    stats = {'today_sales': today_sales, 'today_orders': today_orders, 'avg_spend': (today_sales / today_orders) if today_orders > 0 else 0, 'occupied_tables': Table.query.filter_by(status='occupied').count(), 'total_tables': Table.query.count()}
    return render_template('dashboard.html', stats=stats)

@app.route('/admin/menu')
@login_required
def admin_menu():
    sorted_categories = Category.query.order_by(Category.sort_order).all()
    categorized_items = []
    for category in sorted_categories:
        items = MenuItem.query.filter_by(category_id=category.id).order_by(MenuItem.sort_order).all()
        categorized_items.append({'category_obj': category, 'item_list': items})
    return render_template('admin_menu.html', categorized_items=categorized_items)

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

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    today_start = datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    today_orders = Order.query.filter(Order.timestamp >= today_start).count()
    today_revenue = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp >= today_start, Order.status != 'cancelled').scalar() or 0
    popular_items_query = db.session.query(Order.item_name, func.count(Order.id).label('total_quantity')).filter(Order.timestamp >= today_start, Order.status != 'cancelled').group_by(Order.item_name).order_by(desc('total_quantity')).limit(5).all()
    popular_items = [{'item_name': name, 'total_quantity': count} for name, count in popular_items_query]
    return render_template('admin_analytics.html', today_orders=today_orders, today_revenue=today_revenue, popular_items=popular_items)

@app.route('/admin/security')
@login_required
def admin_security():
    recent_logs = []
    return render_template('admin_security.html', recent_logs=recent_logs)

# --- APIエンドポイント ---
@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    data = request.json
    table_id = session.get('table_id')
    persistent_session_id = session.get('persistent_session_id')
    individual_session_id = session.get('individual_session_id')
    items = data.get('items')
    
    print(f"Debug - session table_id: {table_id}, items: {items}")  # デバッグ用
    
    if not all([table_id, persistent_session_id, items]): 
        print(f"Debug - Missing session info: table_id={table_id}, persistent_session_id={persistent_session_id}, items={items}")
        return jsonify(success=False, message="セッション情報が無効です。"), 400
    
    # 注文を処理する前に、テーブルが存在するか確認する
    table = db.session.get(Table, table_id)
    if not table:
        session.clear()
        return jsonify(success=False, message="このテーブルは現在ご利用いただけません。お手数ですが、再度QRコードを読み取ってください。"), 400

    try:
        for item_id, item_data in items.items():
            menu_item = db.session.get(MenuItem, int(item_id))
            if menu_item and item_data.get('quantity', 0) > 0:
                for _ in range(item_data['quantity']):
                    order = Order(
                        item_name=menu_item.name, 
                        item_price=menu_item.price, 
                        table_id=table_id, 
                        persistent_session_id=persistent_session_id,
                        individual_session_id=individual_session_id
                    )
                    db.session.add(order)
                menu_item.popularity_count += item_data['quantity']
        
        table.last_accessed = datetime.datetime.now(JST)
        db.session.commit()
        print(f"Debug - Order submitted successfully for table {table_id}")
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        print(f"注文送信エラー: {e}")
        return jsonify(success=False, message="注文の処理中にエラーが発生しました。"), 500

@app.route('/api/customer/orders')
def api_customer_orders():
    persistent_session_id = session.get('persistent_session_id')
    table_id = session.get('table_id')
    show_all = request.args.get('show_all', 'false').lower() == 'true'
    
    if not persistent_session_id or not table_id:
        return jsonify(success=False, message="セッション情報がありません。")
    
    if show_all:
        orders = Order.query.filter_by(persistent_session_id=persistent_session_id).order_by(Order.timestamp.asc()).all()
    else:
        individual_session_id = session.get('individual_session_id')
        if individual_session_id:
            orders = Order.query.filter_by(
                persistent_session_id=persistent_session_id,
                individual_session_id=individual_session_id
            ).order_by(Order.timestamp.asc()).all()
        else:
            orders = Order.query.filter_by(persistent_session_id=persistent_session_id).order_by(Order.timestamp.asc()).all()
    
    order_list = []
    for o in orders:
        order_list.append({
            'name': o.item_name, 
            'price': o.item_price, 
            'status': o.status,
            'timestamp': o.timestamp.strftime('%H:%M'),
            'is_current_session': o.individual_session_id == session.get('individual_session_id')
        })
    
    total = sum(o.item_price for o in orders if o.status != 'cancelled')
    return jsonify(success=True, orders=order_list, total=total)

@app.route('/api/kitchen/orders')
@login_required
def api_kitchen_orders():
    orders_query = Order.query.filter(Order.status.in_(['pending', 'preparing'])).order_by(Order.timestamp.asc()).all()
    output = [{'id': o.id, 'table_name': o.table.name, 'item_name': o.item_name, 'status': o.status, 'timestamp': o.timestamp.isoformat()} for o in orders_query]
    pending_orders_count = Order.query.filter_by(status='pending').count()
    preparing_orders_count = Order.query.filter_by(status='preparing').count()
    ready_orders_count = Order.query.filter_by(status='ready').count()
    total_orders_today_count = Order.query.filter(Order.timestamp >= datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)).count()
    stats = {'pending_orders': pending_orders_count, 'preparing_orders': preparing_orders_count, 'ready_orders': ready_orders_count, 'total_orders': total_orders_today_count}
    return jsonify(success=True, orders=output, stats=stats)

@app.route('/api/kitchen/orders/<int:order_id>/status', methods=['PUT'])
@login_required
def update_order_status(order_id):
    data = request.json
    new_status = data.get('status')
    order_to_update = db.session.get(Order, order_id)
    if not order_to_update: return jsonify(success=False, message="注文が見つかりません。"), 404
    if new_status == 'preparing' and order_to_update.status == 'pending':
        order_to_update.status = new_status
    elif new_status == 'served' and order_to_update.status in ['pending', 'preparing']:
        order_to_update.status = new_status
    else:
        return jsonify(success=False, message="許可されていないステータス変更です。"), 400
    db.session.commit()
    return jsonify(success=True, message=f"注文ステータスを {new_status} に更新しました。")

@app.route('/api/order/complete/<session_id>', methods=['POST'])
@login_required
def api_complete_order(session_id):
    orders = Order.query.filter_by(persistent_session_id=session_id, status='ready').all()
    if not orders: return jsonify(success=False, message="対象の注文が見つかりません。"), 404
    for order in orders: order.status = 'served'
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/guidance/generate', methods=['POST'])
@login_required
def api_generate_guidance_qr():
    data = request.json
    table_name = data.get('table_name')
    if not table_name: return jsonify(success=False, message="テーブル名を入力してください。"), 400
    token = secrets.token_urlsafe(16)
    new_qr = TempQRToken(token=token, table_name=table_name, guest_count=int(data.get('guest_count', 1)))
    db.session.add(new_qr)
    db.session.commit()
    return jsonify(success=True, token=token, table_name=table_name)

@app.route('/api/qr/generate/<int:table_id>', methods=['POST'])
@login_required
def api_generate_table_qr(table_id):
    table = db.session.get(Table, table_id)
    if not table: return jsonify(success=False, message="Table not found"), 404
    
    if not table.active_qr_token:
        table.active_qr_token = secrets.token_urlsafe(16)
    
    if not table.persistent_session_id:
        table.persistent_session_id = secrets.token_hex(16)
    
    db.session.commit()
    return jsonify(success=True, token=table.active_qr_token)

@app.route('/api/tables', methods=['POST'])
@login_required
def api_add_table():
    data = request.json
    name = data.get('name')
    if not name: return jsonify(success=False, message='Table name is required'), 400
    if Table.query.filter_by(name=name).first(): return jsonify(success=False, message='Table name already exists'), 400
    new_table = Table(name=name)
    new_table.active_qr_token = secrets.token_urlsafe(16)
    new_table.persistent_session_id = secrets.token_hex(16)
    db.session.add(new_table)
    db.session.commit()
    return jsonify(success=True, id=new_table.id, name=new_table.name, token=new_table.active_qr_token)

@app.route('/api/tables/<int:table_id>', methods=['DELETE'])
@login_required
def api_delete_table(table_id):
    table = db.session.get(Table, table_id)
    if not table: return jsonify(success=False, message="Table not found"), 404
    db.session.delete(table)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/menu/add', methods=['POST'])
@login_required
def api_add_menu_item():
    data = request.json
    if not all(k in data for k in ['name', 'price', 'category']):
        return jsonify(success=False, message='Missing data'), 400
    
    category_name = data['category']
    category = Category.query.filter_by(name=category_name).first()
    if not category:
        max_cat_order = db.session.query(func.max(Category.sort_order)).scalar()
        new_cat_order = (max_cat_order + 1) if max_cat_order is not None else 0
        category = Category(name=category_name, sort_order=new_cat_order)
        db.session.add(category)
        db.session.flush()
    
    max_item_order = db.session.query(func.max(MenuItem.sort_order)).filter_by(category_id=category.id).scalar()
    new_item_order = (max_item_order + 1) if max_item_order is not None else 0
    
    item = MenuItem(
        name=data['name'], 
        price=int(data['price']), 
        description=data.get('description', ''),
        category_id=category.id, 
        sort_order=new_item_order
    )
    db.session.add(item)
    db.session.commit()
    
    return jsonify(
        success=True, 
        item_id=item.id, 
        name=item.name, 
        price=item.price, 
        category=category.name, 
        active=item.active,
        description=item.description
    )

@app.route('/api/menu/<int:item_id>/update', methods=['PUT'])
@login_required
def api_update_menu_item(item_id):
    try:
        item = db.session.get(MenuItem, item_id)
        if not item:
            return jsonify(success=False, message="メニューが見つかりません。"), 404
        
        data = request.json
        item.name = data.get('name', item.name)
        item.price = data.get('price', item.price)
        item.description = data.get('description', item.description)
        
        db.session.commit()
        return jsonify(success=True, message="メニューを更新しました。")
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"メニューの更新中にエラーが発生しました: {str(e)}"), 500

@app.route('/api/menu/<int:item_id>', methods=['DELETE'])
@login_required
def api_delete_menu_item(item_id):
    try:
        item = db.session.get(MenuItem, item_id)
        if not item:
            return jsonify(success=False, message="メニューが見つかりません。"), 404
        
        item_name = item.name
        related_orders = Order.query.filter_by(item_name=item_name).count()
        
        if related_orders > 0:
            item.active = False
            db.session.commit()
            return jsonify(
                success=True, 
                message=f"メニュー '{item_name}' は注文履歴があるため非表示にしました。完全に削除するには注文履歴を先に削除してください。",
                action="deactivated"
            )
        else:
            db.session.delete(item)
            db.session.commit()
            return jsonify(
                success=True, 
                message=f"メニュー '{item_name}' を完全に削除しました。",
                action="deleted"
            )
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"メニューの削除中にエラーが発生しました: {str(e)}"), 500

@app.route('/api/menu/<int:item_id>/force-delete', methods=['DELETE'])
@login_required
def api_force_delete_menu_item(item_id):
    try:
        item = db.session.get(MenuItem, item_id)
        if not item:
            return jsonify(success=False, message="メニューが見つかりません。"), 404
        
        item_name = item.name
        related_orders = Order.query.filter_by(item_name=item_name).all()
        deleted_orders_count = len(related_orders)
        
        for order in related_orders:
            db.session.delete(order)
        
        db.session.delete(item)
        db.session.commit()
        
        return jsonify(
            success=True, 
            message=f"メニュー '{item_name}' と関連する {deleted_orders_count} 件の注文履歴を削除しました。",
            action="force_deleted",
            deleted_orders=deleted_orders_count
        )
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"メニューの強制削除中にエラーが発生しました: {str(e)}"), 500

@app.route('/api/category/<int:category_id>', methods=['DELETE'])
@login_required
def api_delete_category(category_id):
    try:
        category = db.session.get(Category, category_id)
        if not category: 
            return jsonify(success=False, message="カテゴリが見つかりません。"), 404
        
        category_name = category.name
        item_count = MenuItem.query.filter_by(category_id=category_id).count()
        
        db.session.delete(category)
        db.session.commit()
        
        return jsonify(
            success=True, 
            message=f"カテゴリ '{category_name}' を削除しました。",
            deleted_items=item_count
        )
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"カテゴリの削除中にエラーが発生しました: {str(e)}"), 500

@app.route('/api/menu/toggle/<int:item_id>', methods=['POST'])
@login_required
def api_toggle_menu_item_active(item_id):
    item = db.session.get(MenuItem, item_id)
    if not item: return jsonify(success=False, message="Item not found"), 404
    item.active = not item.active
    db.session.commit()
    return jsonify(success=True, active=item.active)

@app.route('/api/menu/order', methods=['POST'])
@login_required
def update_menu_order():
    data = request.json
    item_ids = data.get('item_ids')
    if not item_ids: return jsonify(success=False, message="No item IDs provided"), 400
    try:
        items_map = {item.id: item for item in MenuItem.query.filter(MenuItem.id.in_(item_ids)).all()}
        for index, item_id_str in enumerate(item_ids):
            item_id = int(item_id_str)
            item = items_map.get(item_id)
            if item: item.sort_order = index
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/category/order', methods=['POST'])
@login_required
def update_category_order():
    data = request.json
    category_ids = data.get('category_ids')
    if not category_ids: return jsonify(success=False, message="No category IDs provided"), 400
    try:
        category_map = {cat.id: cat for cat in Category.query.filter(Category.id.in_(category_ids)).all()}
        for index, cat_id_str in enumerate(category_ids):
            cat_id = int(cat_id_str)
            category = category_map.get(cat_id)
            if category: category.sort_order = index
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/history/orders')
@login_required
def api_history_orders():
    page = request.args.get('page', 1, type=int)
    per_page = 15
    keyword = request.args.get('keyword', '')
    table_name = request.args.get('table', '')
    status = request.args.get('status', '')
    query = Order.query.join(Table).order_by(Order.timestamp.desc())
    if keyword: query = query.filter(Order.item_name.ilike(f'%{keyword}%'))
    if table_name: query = query.filter(Table.name == table_name)
    if status: query = query.filter(Order.status == status)
    total = query.count()
    pages = ceil(total / per_page)
    orders_page = query.paginate(page=page, per_page=per_page, error_out=False)
    result = [{'id': o.id, 'table_name': o.table.name, 'item_name': o.item_name, 'price': o.item_price, 'status': o.status, 'timestamp': o.timestamp.astimezone(JST).strftime('%Y-%m-%d %H:%M')} for o in orders_page.items]
    return jsonify(orders=result, page=page, pages=pages, total=total)

@app.route('/api/order/cancel/<int:order_id>', methods=['POST'])
@login_required
def api_cancel_order(order_id):
    order = db.session.get(Order, order_id)
    if not order: return jsonify(success=False, message="注文が見つかりません。"), 404
    order.status = 'cancelled'
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/dashboard/summary')
@login_required
def api_dashboard_summary():
    today_start = datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    sales_query = db.session.query(func.sum(Order.item_price), func.count(Order.id)).filter(Order.timestamp >= today_start, Order.status != 'cancelled')
    today_sales, today_orders = sales_query.one()
    today_sales = today_sales or 0
    today_orders = today_orders or 0
    avg_spend = (today_sales / today_orders) if today_orders > 0 else 0
    occupied_tables = Table.query.filter_by(status='occupied').count()
    total_tables = Table.query.count()
    popular_items = MenuItem.query.order_by(MenuItem.popularity_count.desc()).limit(5).all()
    return jsonify(today_sales=f"¥{today_sales:,}", today_orders=today_orders, avg_spend=f"¥{avg_spend:,.0f}", occupied_tables=occupied_tables, total_tables=total_tables, popular_items=[{'name': item.name, 'count': item.popularity_count} for item in popular_items])

@app.route('/api/dashboard/sales')
@login_required
def api_dashboard_sales():
    period = request.args.get('period', 'daily')
    today = datetime.datetime.now(JST).date()
    if period == 'monthly':
        start_date = today.replace(day=1) - datetime.timedelta(days=365)
        start_date = start_date.replace(day=1)
        sales_data = db.session.query(func.date_trunc('month', Order.timestamp), func.sum(Order.item_price)).filter(Order.timestamp >= start_date, Order.status != 'cancelled').group_by(func.date_trunc('month', Order.timestamp)).order_by(func.date_trunc('month', Order.timestamp)).all()
        labels = [d.strftime("%Y-%m") for d, _ in sales_data]
        sales = [s for _, s in sales_data]
    else:
        start_date = today - datetime.timedelta(days=29)
        sales_data = db.session.query(func.cast(Order.timestamp, db.Date), func.sum(Order.item_price)).filter(func.cast(Order.timestamp, db.Date) >= start_date, Order.status != 'cancelled').group_by(func.cast(Order.timestamp, db.Date)).order_by(func.cast(Order.timestamp, db.Date)).all()
        date_to_sales = {d.strftime("%Y-%m-%d"): s for d, s in sales_data}
        labels = [(start_date + datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(30)]
        sales = [date_to_sales.get(label, 0) for label in labels]
    return jsonify(labels=labels, sales=sales)

@app.route('/api/sales/reset', methods=['POST'])
@login_required
def api_sales_reset():
    try:
        db.session.query(Order).delete()
        MenuItem.query.update({MenuItem.popularity_count: 0})
        db.session.commit()
        return jsonify(success=True, message="全ての売上データと注文履歴がリセットされました。")
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"リセット中にエラーが発生しました: {str(e)}"), 500

@app.route('/api/kitchen/status')
@login_required
def api_kitchen_status():
    q = Order.query.filter(Order.status.in_(['pending', 'preparing']))
    is_cooking = db.session.query(q.exists()).scalar()
    return jsonify({'cooking_active': is_cooking})

# --- ギャラリールートの追加 ---
@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

# --- ヘルスチェック用エンドポイント ---
@app.route('/health')
def health_check():
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# --- エラーハンドラー ---
@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify(success=False, message='Endpoint not found'), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f"Internal error: {str(error)}")
    if request.path.startswith('/api/'):
        return jsonify(success=False, message='Internal server error'), 500
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    if request.path.startswith('/api/'):
        return jsonify(success=False, message='Access forbidden'), 403
    return render_template('404.html'), 403

# --- データベース初期化コマンド ---
@app.cli.command("init-db")
def init_db_command():
    """データベースを初期化するコマンド"""
    init_database()

if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)