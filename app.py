# app.py

# 既存のインポート
from datetime import datetime, time
from sqlalchemy import func
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
import qrcode
import io
import base64
import json
import pytz # ここを追加: pytzライブラリをインポート

# アプリケーションの初期化
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TIMEZONE'] = 'Asia/Tokyo' # ここを追加: タイムゾーン設定

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Userモデルの定義
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# MenuItemモデルの定義
class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    is_available = db.Column(db.Boolean, default=True)

# Tableモデルの定義
class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    qr_code_data = db.Column(db.String(255), unique=True, nullable=True) # QRコードのURLなど
    orders = db.relationship('Order', backref='table', lazy=True)

# Orderモデルの定義
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    order_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_completed = db.Column(db.Boolean, default=False)
    is_cancelled = db.Column(db.Boolean, default=False) # キャンセル状態を追加

    items = db.relationship('OrderItem', backref='order', lazy=True)

# OrderItemモデルの定義
class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False) # 注文時の価格を保持
    menu_item = db.relationship('MenuItem') # MenuItemへの参照を追加

# DB初期化とユーザー作成（初回デプロイ時などに実行）
@app.before_first_request
def create_tables():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin')
        admin_user.set_password('adminpass') # ここをより強力なパスワードに変更してください
        db.session.add(admin_user)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ルート定義

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('ログインしました！', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('ユーザー名またはパスワードが間違っています。', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ログアウトしました。', 'success')
    return redirect(url_for('index'))

# ダッシュボード
@app.route('/dashboard')
@login_required
def dashboard():
    # タイムゾーンを考慮した現在時刻の取得
    tz = pytz.timezone(app.config.get('TIMEZONE', 'UTC'))
    now_in_tz = datetime.now(tz)
    today_in_tz = now_in_tz.date()

    # 今日の始まりと終わりをタイムゾーン対応で設定
    start_of_day = tz.localize(datetime.combine(today_in_tz, time.min))
    end_of_day = tz.localize(datetime.combine(today_in_tz, time.max))

    # 今日の売上合計 (キャンセルされていない注文のみを対象)
    total_sales_today = db.session.query(func.sum(OrderItem.price * OrderItem.quantity)). \
        join(Order). \
        filter(Order.order_time.between(start_of_day, end_of_day),
               Order.is_cancelled == False). \
        scalar() or 0

    # 今日の注文数 (キャンセルされていない注文のみを対象)
    total_orders_today = Order.query.filter(Order.order_time.between(start_of_day, end_of_day),
                                            Order.is_cancelled == False).count()

    # 今日の平均注文額
    average_order_value_today = (total_sales_today / total_orders_today) if total_orders_today > 0 else 0

    # 今日の人気メニュー (上位5件) (キャンセルされていない注文のみを対象)
    top_selling_items_today = db.session.query(
        MenuItem.name,
        func.sum(OrderItem.quantity).label('total_quantity')
    ). \
        join(OrderItem). \
        join(Order). \
        filter(Order.order_time.between(start_of_day, end_of_day),
               Order.is_cancelled == False). \
        group_by(MenuItem.name). \
        order_by(func.sum(OrderItem.quantity).desc()). \
        limit(5).all()

    # 今日の注文履歴（最新10件）
    recent_orders = Order.query.filter(Order.order_time.between(start_of_day, end_of_day)). \
        order_by(Order.order_time.desc()). \
        limit(10).all()

    # 卓ごとの現在の注文状況
    tables_with_orders = []
    tables = Table.query.all()
    for table in tables:
        current_orders = Order.query.filter_by(table_id=table.id, is_completed=False, is_cancelled=False).all()
        total_amount = sum(item.price * item.quantity for order in current_orders for item in order.items)
        tables_with_orders.append({
            'id': table.id,
            'name': table.name,
            'current_orders': current_orders,
            'total_amount': total_amount
        })

    return render_template('dashboard.html',
                           total_sales_today=total_sales_today,
                           total_orders_today=total_orders_today,
                           average_order_value_today=average_order_value_today,
                           top_selling_items_today=top_selling_items_today,
                           recent_orders=recent_orders,
                           tables_with_orders=tables_with_orders)

# キッチン画面
@app.route('/kitchen')
@login_required
def kitchen():
    # 未完了の注文をテーブルごとに取得
    tables_with_uncompleted_orders = []
    tables = Table.query.all()
    for table in tables:
        uncompleted_orders = Order.query.filter_by(table_id=table.id, is_completed=False, is_cancelled=False).order_by(Order.order_time.asc()).all()
        if uncompleted_orders:
            tables_with_uncompleted_orders.append({
                'table': table,
                'orders': uncompleted_orders
            })
    return render_template('kitchen.html', tables_with_uncompleted_orders=tables_with_uncompleted_orders)

# 注文完了API
@app.route('/api/order/<int:order_id>/complete', methods=['POST'])
@login_required
def complete_order(order_id):
    order = Order.query.get_or_404(order_id)
    order.is_completed = True
    db.session.commit()
    flash(f'注文 {order.id} を完了しました。', 'success')
    return jsonify(success=True)

# 注文キャンセルAPI
@app.route('/api/order/<int:order_id>/cancel', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = Order.query.get_or_404(order_id)
    order.is_cancelled = True
    db.session.commit()
    flash(f'注文 {order.id} をキャンセルしました。', 'success')
    return jsonify(success=True)

# キッチンステータスAPI
@app.route('/api/kitchen/status')
def check_kitchen_status():
    cooking_active = Order.query.filter_by(is_completed=False, is_cancelled=False).count() > 0
    return jsonify(cooking_active=cooking_active)

# 案内管理
@app.route('/admin/guidance')
@login_required
def admin_guidance():
    tables = Table.query.all()
    return render_template('admin_guidance.html', tables=tables)

# QRコード生成API
@app.route('/generate_qr/<int:table_id>')
@login_required
def generate_qr(table_id):
    table = Table.query.get_or_404(table_id)
    # アプリケーションのベースURLを取得
    base_url = request.url_root.rstrip('/')
    qr_data = f"{base_url}/table/{table.id}/menu"

    # QRコードを生成
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    
    # 画像をバイトストリームに保存し、base64エンコード
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    table.qr_code_data = qr_data # QRコードデータをテーブルに保存
    db.session.commit()

    return jsonify(qr_code_image=f"data:image/png;base64,{qr_base64}", qr_data=qr_data)

# メニュー管理
@app.route('/admin/menu')
@login_required
def admin_menu():
    categories = db.session.query(MenuItem.category).distinct().all()
    categories = [c[0] for c in categories]
    menu_items = MenuItem.query.all()
    return render_template('admin_menu.html', menu_items=menu_items, categories=categories)

@app.route('/admin/menu/add', methods=['POST'])
@login_required
def add_menu_item():
    name = request.form['name']
    description = request.form['description']
    price = int(request.form['price'])
    category = request.form['category']
    new_item = MenuItem(name=name, description=description, price=price, category=category)
    db.session.add(new_item)
    db.session.commit()
    flash('メニュー項目が追加されました！', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/menu/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_menu_item(item_id):
    item = MenuItem.query.get_or_404(item_id)
    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.price = int(request.form['price'])
        item.category = request.form['category']
        item.is_available = 'is_available' in request.form
        db.session.commit()
        flash('メニュー項目が更新されました！', 'success')
        return redirect(url_for('admin_menu'))
    categories = db.session.query(MenuItem.category).distinct().all()
    categories = [c[0] for c in categories]
    return render_template('edit_menu_item.html', item=item, categories=categories)

@app.route('/admin/menu/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_menu_item(item_id):
    item = MenuItem.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('メニュー項目が削除されました！', 'success')
    return redirect(url_for('admin_menu'))

# 卓管理
@app.route('/admin/tables')
@login_required
def admin_tables():
    tables = Table.query.all()
    return render_template('admin_tables.html', tables=tables)

@app.route('/admin/tables/add', methods=['POST'])
@login_required
def add_table():
    table_name = request.form['name']
    new_table = Table(name=table_name)
    db.session.add(new_table)
    db.session.commit()
    flash(f'卓 "{table_name}" が追加されました！', 'success')
    return redirect(url_for('admin_tables'))

@app.route('/admin/tables/delete/<int:table_id>', methods=['POST'])
@login_required
def delete_table(table_id):
    table = Table.query.get_or_404(table_id)
    # 関連する注文アイテムを削除
    for order in table.orders:
        OrderItem.query.filter_by(order_id=order.id).delete()
    # 関連する注文を削除
    Order.query.filter_by(table_id=table.id).delete()
    
    db.session.delete(table)
    db.session.commit()
    flash(f'卓 "{table.name}" が削除されました！', 'success')
    return redirect(url_for('admin_tables'))

# 注文履歴
@app.route('/admin/history')
@login_required
def admin_history():
    # キャンセルされた注文を表示するかどうかのフィルタリング
    show_cancelled = request.args.get('show_cancelled', 'false').lower() == 'true'
    
    query = Order.query.order_by(Order.order_time.desc())
    
    if not show_cancelled:
        query = query.filter_by(is_cancelled=False)
        
    orders = query.all()
    
    return render_template('admin_history.html', orders=orders, show_cancelled=show_cancelled)

# お客様向けQRコード認証
@app.route('/qr_auth', methods=['GET'])
def qr_auth():
    table_id = request.args.get('table_id')
    if table_id:
        table = Table.query.get(table_id)
        if table:
            # 新しいセッションIDを生成してテーブルに紐付け（必要であれば）
            # ここではシンプルにtable_idをセッションに保存
            session['table_id'] = table_id
            session['session_id'] = str(uuid.uuid4()) # ユニークなセッションIDを生成
            flash(f'卓 {table.name} に接続しました。', 'success')
            return redirect(url_for('table_menu', table_id=table_id))
        else:
            flash('無効な卓IDです。', 'danger')
    return redirect(url_for('index')) # QRコードにtable_idがない場合や無効な場合

# お客様向けメニュー表示
@app.route('/table/<int:table_id>/menu')
def table_menu(table_id):
    # セッションのtable_idとURLのtable_idが一致するか確認
    if 'table_id' not in session or int(session['table_id']) != table_id:
        flash('この卓へのアクセスは許可されていません。QRコードを再スキャンしてください。', 'danger')
        return redirect(url_for('index'))

    table = Table.query.get_or_404(table_id)
    categories = db.session.query(MenuItem.category).distinct().all()
    categories = [c[0] for c in categories]
    menu_items = MenuItem.query.filter_by(is_available=True).all()
    
    # 現在のテーブルの未完了注文を取得
    current_orders = Order.query.filter_by(table_id=table.id, is_completed=False, is_cancelled=False).all()
    
    # カートの内容を計算
    cart_items = {}
    for order in current_orders:
        for item in order.items:
            if item.menu_item_id in cart_items:
                cart_items[item.menu_item_id]['quantity'] += item.quantity
            else:
                cart_items[item.menu_item_id] = {
                    'name': item.menu_item.name,
                    'price': item.price,
                    'quantity': item.quantity
                }
    
    total_cart_amount = sum(item['price'] * item['quantity'] for item in cart_items.values())

    return render_template('table_menu.html', 
                           table=table, 
                           menu_items=menu_items, 
                           categories=categories,
                           cart_items=cart_items,
                           total_cart_amount=total_cart_amount)

# お客様からの注文追加API
@app.route('/table/<int:table_id>/add_to_cart', methods=['POST'])
def add_to_cart(table_id):
    if 'table_id' not in session or int(session['table_id']) != table_id:
        return jsonify(success=False, message='セッションが無効です。'), 403

    data = request.get_json()
    menu_item_id = data.get('menu_item_id')
    quantity = data.get('quantity')

    if not menu_item_id or not quantity or quantity <= 0:
        return jsonify(success=False, message='無効なリクエストです。'), 400

    menu_item = MenuItem.query.get(menu_item_id)
    if not menu_item or not menu_item.is_available:
        return jsonify(success=False, message='メニュー項目が見つからないか、現在利用できません。'), 404

    # 新しい注文を作成（または既存の未完了注文に追加）
    # ここではシンプルに、注文ごとに新しいOrderを作成します。
    # より高度な実装では、未完了のOrderを一つだけ保持し、そこにOrderItemを追加していく形も考えられます。
    
    # 現在のテーブルの未完了注文を取得
    current_order = Order.query.filter_by(table_id=table_id, is_completed=False, is_cancelled=False).first()

    if not current_order:
        current_order = Order(table_id=table_id)
        db.session.add(current_order)
        db.session.commit() # OrderをコミットしてIDを取得

    order_item = OrderItem(
        order_id=current_order.id,
        menu_item_id=menu_item.id,
        quantity=quantity,
        price=menu_item.price
    )
    db.session.add(order_item)
    db.session.commit()

    flash(f'{menu_item.name}を{quantity}個カートに追加しました！', 'success')
    return jsonify(success=True, message='カートに追加しました。')

# お客様からの注文削除API
@app.route('/table/<int:table_id>/remove_from_cart', methods=['POST'])
def remove_from_cart(table_id):
    if 'table_id' not in session or int(session['table_id']) != table_id:
        return jsonify(success=False, message='セッションが無効です。'), 403

    data = request.get_json()
    menu_item_id = data.get('menu_item_id')
    
    if not menu_item_id:
        return jsonify(success=False, message='無効なリクエストです。'), 400

    # 現在のテーブルの未完了注文を取得
    current_order = Order.query.filter_by(table_id=table_id, is_completed=False, is_cancelled=False).first()

    if not current_order:
        return jsonify(success=False, message='カートに商品がありません。'), 404

    # 該当するOrderItemを削除
    order_item_to_remove = OrderItem.query.filter_by(
        order_id=current_order.id,
        menu_item_id=menu_item_id
    ).first()

    if not order_item_to_remove:
        return jsonify(success=False, message='カートにその商品はありません。'), 404
    
    # 数量が複数ある場合は1つ減らす、1つの場合は削除
    if order_item_to_remove.quantity > 1:
        order_item_to_remove.quantity -= 1
    else:
        db.session.delete(order_item_to_remove)
    
    db.session.commit()

    # もし注文アイテムが全て削除されたら、親のOrderも削除
    if not current_order.items:
        db.session.delete(current_order)
        db.session.commit()

    flash('カートから商品を削除しました。', 'success')
    return jsonify(success=True, message='カートから削除しました。')

# ギャラリーページ
@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # 管理者ユーザーが存在しない場合のみ作成
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('adminpass') # 本番環境ではより強力なパスワードを設定してください
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))