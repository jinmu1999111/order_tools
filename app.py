import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)
app.secret_key = os.urandom(24)
# Renderの環境変数からデータベースURLを読み込む
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
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
    password_hash = db.Column(db.String(128))
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

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    orders = db.relationship('Order', backref='table', lazy=True, cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending, served
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)

# --- ログインマネージャー ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 初回起動時にデータベースと管理者ユーザーを作成するコマンド ---
@app.cli.command("init-db")
def init_db_command():
    """データベーステーブルと管理者ユーザーを作成します。"""
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', is_admin=True)
        admin.set_password('password123')
        db.session.add(admin)
        db.session.commit()
        print("管理者ユーザーを作成しました。")
    print("データベースを初期化しました。")

# --- Webページのルート ---
@app.route('/')
def index():
    tables = Table.query.order_by(Table.name).all()
    return render_template('index.html', tables=tables)

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    table = Table.query.get_or_404(table_id)
    menu_items = MenuItem.query.filter_by(active=True).all()
    categorized_menu = {}
    for item in menu_items:
        if item.category not in categorized_menu:
            categorized_menu[item.category] = []
        categorized_menu[item.category].append(item)
    return render_template('table_menu.html', table=table, categorized_menu=categorized_menu)

# --- API ---
@app.route('/api/order/submit', methods=['POST'])
def submit_order():
    data = request.get_json()
    table_id = data.get('table_id')
    cart_items = data.get('cart', [])
    table = Table.query.get(table_id)
    if not table:
        return jsonify(success=False), 404
    for item in cart_items:
        new_order = Order(
            item_name=item['name'],
            item_price=item['price'],
            table_id=table_id
        )
        db.session.add(new_order)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/table_status/<int:table_id>')
def table_status(table_id):
    orders = Order.query.filter_by(table_id=table_id).all()
    total_price = sum(order.item_price for order in orders)
    orders_data = [{'id': o.id, 'name': o.item_name, 'status': o.status} for o in orders]
    return jsonify(orders=orders_data, total_price=total_price)

# --- 管理者用ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
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
    pending_orders = Order.query.filter_by(status='pending').order_by(Order.timestamp).all()
    return render_template('kitchen.html', pending_orders=pending_orders)

# 新機能：注文履歴ページ
@app.route('/admin/history')
@login_required
def admin_history():
    tables = Table.query.all()
    return render_template('admin_history.html', tables=tables)

# 新機能：注文履歴の削除API
@app.route('/api/history/clear/<int:table_id>', methods=['POST'])
@login_required
def clear_history(table_id):
    Order.query.filter_by(table_id=table_id).delete()
    db.session.commit()
    flash(f'テーブルID:{table_id} の注文履歴を削除しました。', 'success')
    return redirect(url_for('admin_history'))

# メニュー管理
@app.route('/admin/menu')
@login_required
def admin_menu():
    menu_items = MenuItem.query.all()
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
    return redirect(url_for('admin_menu'))

@app.route('/admin/menu/delete/<int:item_id>')
@login_required
def delete_menu_item(item_id):
    item = MenuItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
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
    new_table = Table(name=request.form.get('name'))
    db.session.add(new_table)
    db.session.commit()
    return redirect(url_for('admin_tables'))

# ... 他のルートも同様にデータベースを使うように修正 ...