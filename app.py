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
from math import ceil
from flask_migrate import Migrate

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-fixed-secret-key-change-this-in-production-1234567890')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/test.db')
if db_url.startswith("postgres://"):
    # SQLAlchemy 2.0+ の形式に変換
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)
instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
os.makedirs(instance_path, exist_ok=True)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
JST = pytz.timezone('Asia/Tokyo')

# --- テンプレートで使用するグローバル変数を設定 ---
@app.context_processor
def inject_globals():
    """全てのテンプレートでJSTを使えるようにする"""
    return dict(JST=JST)

# --- ログイン機能の設定 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "このページにアクセスするにはログインが必要です。"

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

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    active = db.Column(db.Boolean, default=True)
    popularity_count = db.Column(db.Integer, default=0)
    sort_order = db.Column(db.Integer, default=0, nullable=False)

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
    status = db.Column(db.String(20), default='pending')
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
    temp_token = TempQRToken.query.filter_by(token=token).first()
    if temp_token and temp_token.is_valid():
        table = Table.query.filter_by(name=temp_token.table_name).first()
        if not table:
            table = Table(name=temp_token.table_name)
            db.session.add(table)
            db.session.flush()
        session['table_id'] = table.id
        session['session_id'] = secrets.token_hex(16)
        table.status = 'occupied'
        temp_token.used = True
        db.session.commit()
        return redirect(url_for('table_menu', table_id=table.id))
    table = Table.query.filter_by(active_qr_token=token).first()
    if table and (not table.qr_token_expiry or table.qr_token_expiry > datetime.datetime.now(JST)):
        session['session_id'] = secrets.token_hex(16)
        session['table_id'] = table.id
        table.status = 'occupied'
        db.session.commit()
        return redirect(url_for('table_menu', table_id=table.id))
    flash('QRコードが無効か期限切れです。', 'danger')
    return redirect(url_for('index'))

def get_menu_data(sort_by='category'):
    if sort_by == 'popularity':
        items = MenuItem.query.filter_by(active=True).order_by(MenuItem.popularity_count.desc()).all()
        return {'items': items}
    else:
        menu_items = MenuItem.query.filter_by(active=True).order_by(MenuItem.category, MenuItem.sort_order).all()
        categorized_menu = defaultdict(list)
        for item in menu_items:
            categorized_menu[item.category].append(item)
        return {'categorized_menu': categorized_menu}

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    if not session.get('table_id') == table_id and not current_user.is_authenticated:
        abort(403)
    table = db.session.get(Table, table_id)
    if not table: abort(404)
    menu_data = get_menu_data()
    return render_template('table_menu.html', table=table, **menu_data)

@app.route('/table/<int:table_id>/menu_partial')
def table_menu_partial(table_id):
    sort_by = request.args.get('sort_by', 'category')
    menu_data = get_menu_data(sort_by)
    if sort_by == 'popularity':
        return render_template('_menu_popular.html', items=menu_data['items'])
    else:
        return render_template('_menu_category.html', categorized_menu=menu_data['categorized_menu'])

# --- 管理者ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
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
    # 初期統計データを計算 (ここではまだ全てのステータスを計算)
    today_start = datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    
    pending_orders = Order.query.filter_by(status='pending').count()
    preparing_orders = Order.query.filter_by(status='preparing').count()
    ready_orders = Order.query.filter_by(status='ready').count() # readyもカウントはするが、表示はしない
    total_orders = Order.query.filter(Order.timestamp >= today_start).count()
    
    stats = {
        'pending_orders': pending_orders,
        'preparing_orders': preparing_orders,
        'ready_orders': ready_orders, # frontendで表示しないようにする
        'total_orders': total_orders
    }
    
    return render_template('kitchen.html', stats=stats)


@app.route('/dashboard')
@login_required
def dashboard():
    # タイムゾーンを考慮した現在時刻の取得
    tz = pytz.timezone(app.config.get('TIMEZONE', 'UTC')) # 修正: app.configからTIMEZONEを取得
    now_in_tz = datetime.datetime.now(tz) # 修正: datetime.datetime を使用
    today_in_tz = now_in_tz.date()

    # 今日の始まりと終わりをタイムゾーン対応で設定
    start_of_day = tz.localize(datetime.datetime.combine(today_in_tz, datetime.time.min)) # 修正: datetime.datetime.combine を使用
    end_of_day = tz.localize(datetime.datetime.combine(today_in_tz, datetime.time.max)) # 修正: datetime.datetime.combine を使用

    # 今日の売上合計 (キャンセルされていない注文のみを対象)
    total_sales_today = db.session.query(func.sum(Order.item_price)). \
        filter(Order.timestamp.between(start_of_day, end_of_day),
               Order.status != 'cancelled'). \
        scalar() or 0

    # 今日の注文数 (キャンセルされていない注文のみを対象)
    total_orders_today = Order.query.filter(Order.timestamp.between(start_of_day, end_of_day),
                                            Order.status != 'cancelled').count()

    # 今日の平均注文額
    average_order_value_today = (total_sales_today / total_orders_today) if total_orders_today > 0 else 0

    # 今日の人気メニュー (上位5件) (キャンセルされていない注文のみを対象)
    popular_items_query = db.session.query(
        MenuItem.name,
        func.sum(Order.item_price).label('total_sales') # ここはtotal_quantityが適切か確認
    ). \
        join(Order, Order.item_name == MenuItem.name). \ # OrderItemモデルがないため簡略化
        filter(Order.timestamp.between(start_of_day, end_of_day),
               Order.status != 'cancelled'). \
        group_by(MenuItem.name). \
        order_by(func.sum(Order.item_price).desc()). \
        limit(5).all()

    #popular_items_today_formatted = [{'name': item.name, 'count': item.total_sales} for item in popular_items_query]
    # ダッシュボードには合計数量が欲しい場合が多いため、item_nameと集計した数量で対応
    popular_items_today_formatted = db.session.query(
        Order.item_name,
        func.count(Order.id).label('total_quantity_sold')
    ).filter(
        Order.timestamp.between(start_of_day, end_of_day),
        Order.status != 'cancelled'
    ).group_by(Order.item_name).order_by(func.count(Order.id).desc()).limit(5).all()


    # 卓ごとの現在の注文状況
    occupied_tables_count = Table.query.filter_by(status='occupied').count()
    total_tables_count = Table.query.count()

    return render_template('dashboard.html',
                           today_sales=total_sales_today, # テンプレート変数名を修正
                           today_orders=total_orders_today, # テンプレート変数名を修正
                           avg_spend=average_order_value_today, # テンプレート変数名を修正
                           popular_items=popular_items_today_formatted, # テンプレート変数名を修正
                           occupied_tables=occupied_tables_count, # テンプレート変数名を修正
                           total_tables=total_tables_count # テンプレート変数名を修正
                           )


@app.route('/admin/menu')
@login_required
def admin_menu():
    menu_items_query = MenuItem.query.order_by(MenuItem.category, MenuItem.sort_order).all()
    categorized_items = defaultdict(list)
    for item in menu_items_query:
        categorized_items[item.category].append(item)
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
    # 注文履歴の表示フィルタリングロジック (show_cancelled パラメータ)
    show_cancelled = request.args.get('show_cancelled', 'false').lower() == 'true'
    query = Order.query.order_by(Order.timestamp.desc())
    if not show_cancelled:
        query = query.filter_by(status='cancelled') # is_cancelledがFalseのものを表示
    orders_data = query.all()

    # 注文アイテムの情報を取得して結合
    history_orders = []
    for order in orders_data:
        # OrderItemモデルがないため、Order.item_name, Order.item_price を直接使用
        # 実際にはOrder.items (relationship) を使用し、OrderItemの情報を取得する
        history_orders.append({
            'id': order.id,
            'table_name': order.table.name,
            'item_name': order.item_name, # Orderモデルに直接あると仮定
            'item_price': order.item_price, # Orderモデルに直接あると仮定
            'status': order.status,
            'timestamp': order.timestamp
        })
    
    return render_template('admin_history.html', orders=history_orders, tables=tables, show_cancelled=show_cancelled)

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    return render_template('admin_guidance.html')

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    """売上統計ページ"""
    today_start = datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    
    today_orders = Order.query.filter(
        Order.timestamp >= today_start
    ).count()
    
    today_revenue = db.session.query(func.sum(Order.item_price)).filter(
        Order.timestamp >= today_start,
        Order.status != 'cancelled'
    ).scalar() or 0
    
    # 人気メニューの取得
    popular_items_query = db.session.query(
        Order.item_name, 
        func.count(Order.id).label('total_quantity')
    ).filter(
        Order.timestamp >= today_start,
        Order.status != 'cancelled'
    ).group_by(Order.item_name).order_by(desc('total_quantity')).limit(5).all()
    
    popular_items = [
        {'item_name': name, 'total_quantity': count} 
        for name, count in popular_items_query
    ]
    
    return render_template('admin_analytics.html', 
                         today_orders=today_orders,
                         today_revenue=today_revenue,
                         popular_items=popular_items)

@app.route('/admin/security')
@login_required
def admin_security():
    """セキュリティログページ"""
    recent_logs = []
    return render_template('admin_security.html', recent_logs=recent_logs)

# --- APIエンドポイント ---
@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    data = request.json
    table_id = session.get('table_id')
    session_id = session.get('session_id')
    items = data.get('items')
    if not all([table_id, session_id, items]): return jsonify(success=False, message="セッション情報が無効です。"), 400
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
        total = sum(o.item_price for o in orders if o.status != 'cancelled')
        return jsonify(success=True, orders=order_list, total=total)
    return jsonify(success=False, message="注文履歴がありません。")

@app.route('/api/kitchen/orders')
@login_required
def api_kitchen_orders():
    # 表示する注文ステータスをpendingとpreparingに限定
    orders_query = Order.query.filter(
        and_(Order.status.in_(['pending', 'preparing']))
    ).order_by(Order.timestamp.asc()).all()
    
    # セッションIDごとに注文をグループ化
    orders_by_session = defaultdict(list)
    for o in orders_query:
        orders_by_session[o.session_id].append(o)
    
    output = []
    for session_id, orders in orders_by_session.items():
        if not orders:
            continue
        
        # セッション内の全注文アイテムをカウント
        item_counts = defaultdict(int)
        for item in orders:
            item_counts[item.item_name] += 1
            
        # そのセッションの「最も進んだ」ステータスを決定
        current_status = 'pending'
        if any(o.status == 'preparing' for o in orders):
            current_status = 'preparing'

        output.append({
            'id': orders[0].id,
            'session_id': session_id,
            'table_number': orders[0].table.name,
            'created_at': orders[0].timestamp.isoformat(),
            'status': current_status,
            'items': [{'name': name, 'quantity': qty} for name, qty in item_counts.items()]
        })

    # 表示順序を調整 (pending -> preparing)
    output.sort(key=lambda x: (
        0 if x['status'] == 'pending' else
        1 if x['status'] == 'preparing' else 2, # 他のステータスは表示されないが、念のため
        x['created_at']
    ))

    # 各ステータスごとの注文数を計算
    pending_orders_count = Order.query.filter_by(status='pending').count()
    preparing_orders_count = Order.query.filter_by(status='preparing').count()
    # ready_orders_countは画面表示から除外するため、ここでは直接使用しないが、statsには含める
    ready_orders_count = Order.query.filter_by(status='ready').count() 
    total_orders_today_count = Order.query.filter(
        Order.timestamp >= datetime.datetime.now(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()

    stats = {
        'pending_orders': pending_orders_count,
        'preparing_orders': preparing_orders_count,
        'ready_orders': ready_orders_count, # 画面では表示しないがデータとしては渡す
        'total_orders': total_orders_today_count
    }

    return jsonify(success=True, orders=output, stats=stats)

@app.route('/api/kitchen/orders/<int:order_id>/status', methods=['PUT'])
@login_required
def update_order_status(order_id):
    data = request.json
    new_status = data.get('status')

    order_to_update = db.session.get(Order, order_id)
    
    if not order_to_update:
        return jsonify(success=False, message="注文が見つかりません。"), 404

    # 関連する同じセッションIDのすべての注文のステータスを更新
    orders_in_session = Order.query.filter_by(session_id=order_to_update.session_id).all()
    
    for order in orders_in_session:
        if new_status == 'preparing' and order.status == 'pending':
            order.status = new_status
        elif new_status == 'served' and (order.status == 'preparing' or order.status == 'pending'): # pendingからも直接servedに変更できるようにする
            order.status = new_status
    
    db.session.commit()
    return jsonify(success=True, message=f"注文ステータスを {new_status} に更新しました。")

@app.route('/api/order/complete/<session_id>', methods=['POST'])
@login_required
def api_complete_order(session_id):
    # このAPIは、セッション単位での完了（Ready->Served）として残しておくが、
    # 今回の簡素化されたキッチンフローでは直接使用されない。
    orders = Order.query.filter_by(session_id=session_id, status='ready').all()
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
    table.active_qr_token = secrets.token_urlsafe(16)
    table.qr_token_expiry = datetime.datetime.now(JST) + datetime.timedelta(hours=8)
    db.session.commit()
    return jsonify(success=True, token=table.active_qr_token, expiry=table.qr_token_expiry.isoformat())

@app.route('/api/tables', methods=['POST'])
@login_required
def api_add_table():
    data = request.json
    name = data.get('name')
    if not name: return jsonify(success=False, message='Table name is required'), 400
    if Table.query.filter_by(name=name).first(): return jsonify(success=False, message='Table name already exists'), 400
    new_table = Table(name=name)
    new_table.active_qr_token = secrets.token_urlsafe(16)
    new_table.qr_token_expiry = datetime.datetime.now(JST) + datetime.timedelta(hours=8)
    db.session.add(new_table)
    db.session.commit()
    return jsonify(success=True, id=new_table.id, name=new_table.name, 
                   token=new_table.active_qr_token, 
                   expiry=new_table.qr_token_expiry.isoformat())

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
    if not all(k in data for k in ['name', 'price', 'category']): return jsonify(success=False, message='Missing data'), 400
    max_sort_order = db.session.query(func.max(MenuItem.sort_order)).filter_by(category=data['category']).scalar()
    new_sort_order = (max_sort_order + 1) if max_sort_order is not None else 0
    item = MenuItem(name=data['name'], price=int(data['price']), category=data['category'], sort_order=new_sort_order)
    db.session.add(item)
    db.session.commit()
    return jsonify(success=True, item_id=item.id, name=item.name, price=item.price, category=item.category, active=item.active)

@app.route('/api/menu/<int:item_id>', methods=['DELETE'])
@login_required
def api_delete_menu_item(item_id):
    item = db.session.get(MenuItem, item_id)
    if not item: return jsonify(success=False, message="Item not found"), 404
    db.session.delete(item)
    db.session.commit()
    return jsonify(success=True)

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
            item = items_map.get(item)
            if item: 
                item.sort_order = index
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
    # ここに画像ギャラリーのコンテンツを実装します
    return render_template('gallery.html')

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

# --- データベース初期化コマンド ---
@app.cli.command("init-db")
def init_db_command():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('password123')
            db.session.add(admin_user)
            print("管理者アカウントを作成しました: admin / password123")
        if Table.query.count() == 0:
            for i in range(1, 6):
                table = Table(name=f'{i}番テーブル')
                table.active_qr_token = secrets.token_urlsafe(16)
                table.qr_token_expiry = datetime.datetime.now(JST) + datetime.timedelta(hours=8)
                db.session.add(table)
            print("サンプルテーブルを作成しました。")
        db.session.commit()
        print("データベースの初期化・更新が完了しました。")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)