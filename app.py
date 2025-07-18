import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

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
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

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

# --- Webページのルート ---
@app.route('/')
def index():
    tables = Table.query.order_by(Table.name).all()
    return render_template('index.html', tables=tables)

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    table = Table.query.get_or_404(table_id)
    menu_items = MenuItem.query.filter_by(active=True).order_by(MenuItem.category, MenuItem.name).all()
    
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

    if not table or not cart_items:
        return jsonify(success=False, message="Invalid data"), 400

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
    table = Table.query.get_or_404(table_id)
    orders = table.orders.order_by(Order.timestamp.desc()).all()
    total_price = sum(order.item_price for order in orders)
    orders_data = [{'id': o.id, 'name': o.item_name, 'status': o.status} for o in orders]
    return jsonify(orders=orders_data, total_price=total_price)

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

@app.route('/api/kitchen_status')
@login_required
def kitchen_status():
    pending_orders = db.session.query(Order, Table).join(Table).filter(Order.status == 'pending').order_by(Order.timestamp).all()
    orders_data = []
    for order