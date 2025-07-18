import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# --- アプリケーションの初期設定 ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- ログイン機能の設定 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "このページにアクセスするにはログインが必要です。"

# --- データベースの代わりのデータ ---
class User(UserMixin):
    def __init__(self, id, username, password, is_admin=False):
        self.id = id
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.is_admin = is_admin
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

users = {"1": User(id="1", username="admin", password="password123", is_admin=True)}

menu_items = {
    1: {'name': '日替わりランチ', 'price': 850, 'active': True, 'category': '定食'},
    2: {'name': 'からあげ定食', 'price': 780, 'active': True, 'category': '定食'},
    3: {'name': '生ビール（中）', 'price': 550, 'active': True, 'category': 'ドリンク'},
}
next_menu_id = 4

tables = {
    '1': {'name': '1番卓', 'orders': []},
    '2': {'name': '2番卓', 'orders': []},
}
next_table_id = 3
next_order_id = 1

# --- ログインマネージャーの設定 ---
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# --- Webページのルート設定 ---
@app.route('/')
def index():
    return render_template('index.html', tables=tables)

@app.route('/table/<table_id>')
def table_menu(table_id):
    if table_id not in tables:
        return "テーブルが存在しません", 404
    categorized_menu = {}
    for item_id, item in menu_items.items():
        if item['active']:
            if item['category'] not in categorized_menu:
                categorized_menu[item['category']] = []
            item_data = item.copy()
            item_data['id'] = item_id
            categorized_menu[item['category']].append(item_data)
    return render_template('table_menu.html', table_id=table_id, table_data=tables[table_id], categorized_menu=categorized_menu)

# --- API (JavaScriptから呼ばれる) ---
@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    global next_order_id
    data = request.get_json()
    table_id = data.get('table_id')
    cart_items = data.get('cart', [])

    if table_id not in tables:
        return jsonify(success=False, message="テーブルが見つかりません"), 404

    for item in cart_items:
        new_order = {
            'id': next_order_id,
            'item': item,
            'status': 'pending', # 'pending' (調理待ち) or 'served' (提供済)
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
        }
        tables[table_id]['orders'].append(new_order)
        next_order_id += 1
    return jsonify(success=True)

@app.route('/api/order/serve', methods=['POST'])
@login_required
def serve_order():
    data = request.get_json()
    table_id = data.get('table_id')
    order_id = data.get('order_id')

    if table_id in tables:
        for order in tables[table_id]['orders']:
            if order['id'] == order_id:
                order['status'] = 'served'
                return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/api/table_status/<table_id>')
def table_status(table_id):
    if table_id not in tables:
        return jsonify(error="Not Found"), 404
    
    table_data = tables[table_id]
    total_price = sum(order['item']['price'] for order in table_data['orders'])
    return jsonify(orders=table_data['orders'], total_price=total_price)

@app.route('/api/kitchen_status')
@login_required
def kitchen_status():
    all_pending_orders = []
    for table_id, table_data in tables.items():
        for order in table_data['orders']:
            if order['status'] == 'pending':
                order_info = order.copy()
                order_info['table_name'] = table_data['name']
                order_info['table_id'] = table_id
                all_pending_orders.append(order_info)
    
    # 時間の早い順にソート
    all_pending_orders.sort(key=lambda x: x['timestamp'])
    return jsonify(pending_orders=all_pending_orders)


# --- 管理者用ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_to_check = next((user for user in users.values() if user.username == username), None)
        if user_to_check and user_to_check.check_password(password):
            login_user(user_to_check)
            return redirect(url_for('kitchen'))
        else:
            flash('ユーザー名またはパスワードが違います。', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 新機能：キッチン伝票画面
@app.route('/kitchen')
@login_required
def kitchen():
    return render_template('kitchen.html')

# 新機能：卓管理ページ
@app.route('/admin/tables')
@login_required
def admin_tables():
    return render_template('admin_tables.html', tables=tables)

@app.route('/admin/tables/add', methods=['POST'])
@login_required
def add_table():
    global next_table_id
    table_name = request.form.get('name')
    if table_name:
        tables[str(next_table_id)] = {'name': table_name, 'orders': []}
        next_table_id += 1
        flash(f'テーブル「{table_name}」を追加しました。', 'success')
    return redirect(url_for('admin_tables'))

@app.route('/admin/tables/delete/<table_id>')
@login_required
def delete_table(table_id):
    if table_id in tables:
        del tables[table_id]
        flash(f'テーブルを削除しました。', 'success')
    return redirect(url_for('admin_tables'))

# メニュー管理ページ
@app.route('/admin/menu')
@login_required
def admin_menu():
    return render_template('admin_menu.html', menu_items=menu_items)

@app.route('/admin/menu/add', methods=['POST'])
@login_required
def add_menu_item():
    global next_menu_id
    name = request.form.get('name')
    price = int(request.form.get('price'))
    category = request.form.get('category')
    if name and price and category:
        menu_items[next_menu_id] = {'name': name, 'price': price, 'active': True, 'category': category}
        next_menu_id += 1
        flash('メニューを追加しました。', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/menu/delete/<int:item_id>')
@login_required
def delete_menu_item(item_id):
    if item_id in menu_items:
        del menu_items[item_id]
        flash('メニューを削除しました。', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/menu/toggle/<int:item_id>')
@login_required
def toggle_menu_item(item_id):
    if item_id in menu_items:
        menu_items[item_id]['active'] = not menu_items[item_id]['active']
        flash('表示状態を切り替えました。', 'info')
    return redirect(url_for('admin_menu'))

# --- アプリケーションの実行 ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)