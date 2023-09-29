# Kütüphaneleri ve modülleri alfabetik sıraya göre gruplayarak import et
import cProfile
import timeit

import flask
import flask_login
import flask_sqlalchemy
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import config

app = Flask(__name__)
app.config.from_object(config.Config)
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
login.login_message = 'Giriş yapmalısınız.'

# Veritabanı modelleri
class User(db.Model, UserMixin):
    """Kullanıcı veritabanı modeli."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    portfolios = db.relationship('Portfolio', backref='user', lazy=True)

    def set_password(self, password):
        """Şifreyi şifreleyerek password_hash özelliğine atar."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Şifreyi password_hash ile karşılaştırarak doğruluk kontrolü yapar."""
        return check_password_hash(self.password_hash, password)

@login.user_loader
def load_user(id):
    """Kullanıcı oturumunu yönetmek için kullanıcıyı veritabanından yükler."""
    return User.query.get(int(id))

class Portfolio(db.Model):
    """Portföy veritabanı modeli."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stocks = db.relationship('Stock', backref='portfolio', lazy=True)

class Stock(db.Model):
    """Hisse veritabanı modeli."""
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(16), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey('portfolio.id'), nullable=False)

# Ana sayfa
@app.route('/')
def home():
    """Ana sayfayı görüntüler."""
    if current_user.is_authenticated:
        portfolio = Portfolio.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', portfolio=portfolio)
    return render_template('index.html')

# Giriş yapma
@app.route('/login', methods=['POST', 'GET'])
def login():
    """Kullanıcı girişini sağlar."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Kullanıcı adı veya şifre yanlış', 'danger')
    return render_template('login.html')

# Çıkış yapma
@app.route('/logout')
@login_required
def logout():
    """Kullanıcı çıkışını sağlar."""
    logout_user()
    return redirect(url_for('home'))

# Portföy ekleme
@app.route('/add_portfolio', methods=['POST'])
@login_required
def add_portfolio():
    """Portföy ekler."""
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        portfolio = Portfolio(name=name, description=description, user_id=current_user.id)
        db.session.add(portfolio)
        db.session.commit()
    return redirect(url_for('home'))

# Portföy silme
@app.route('/delete_portfolio/<int:portfolio_id>')
@login_required
def delete_portfolio(portfolio_id):
    """Portföy siler."""
    portfolio = Portfolio.query.get_or_404(portfolio_id)
    db.session.delete(portfolio)
    db.session.commit()
    return redirect(url_for('home'))

# Portföy detayı
@app.route('/portfolio/<int:portfolio_id>')
@login_required
def portfolio(portfolio_id):
    """Portföy detayını görüntüler."""
    portfolio = Portfolio.query.get_or_404(portfolio_id)
    stocks = Stock.query.filter_by(portfolio_id=portfolio_id).all()

    api_key = 'your_api_key'
    base_url = 'https://www.alphavantage.co/query'
    market_values = {}
    fundamental_analysis = {}

    for stock in stocks:
        symbol = stock.symbol
        quantity = stock.quantity

        params = {'function': 'TIME_SERIES_DAILY', 'symbol': symbol, 'apikey': api_key}
        response = requests.get(base_url, params=params)
        data = response.json()
        last_date = data['Meta Data']['3. Last Refreshed']
        close_price = float(data['Time Series (Daily)'][last_date]['4. close'])
        market_value = close_price * quantity
        market_values[symbol] = market_value

        params = {'function': 'OVERVIEW', 'symbol': symbol, 'apikey': api_key}
        response = requests.get(base_url, params=params)
        data = response.json()
        eps = float(data['EPS'])
        g = float(data['AnalystTargetPrice']) / float(data['50DayMovingAverage']) - 1
        r = float(data['PERatio']) / 100
        real_value = eps * (1 + g) / (r - g)
        difference = real_value - close_price
        fundamental_analysis[symbol] = difference

    total_market_value = sum(market_values.values())
    
    return render_template('portfolio.html', portfolio=portfolio, stocks=stocks, market_values=market_values, fundamental_analysis=fundamental_analysis, total_market_value=total_market_value)

# Hisse ekleme
@app.route('/add_stock/<int:portfolio_id>', methods=['POST'])
@login_required
def add_stock(portfolio_id):
    """Portföye hisse ekler."""
    if request.method == 'POST':
        symbol = request.form['symbol']
        quantity = request.form['quantity']
        stock = Stock(symbol=symbol, quantity=quantity, portfolio_id=portfolio_id)
        db.session.add(stock)
        db.session.commit()
    return redirect(url_for('portfolio', portfolio_id=portfolio_id))

# Hisse silme
@app.route('/delete_stock/<int:stock_id>')
@login_required
def delete_stock(stock_id):
    """Portföyden hisse siler."""
    stock = Stock.query.get_or_404(stock_id)
    portfolio_id = stock.portfolio_id
    db.session.delete(stock)
    db.session.commit()
    return redirect(url_for('portfolio', portfolio_id=portfolio_id))

# Uygulamayı çalıştır
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, port=5000)
