import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Query infos from database
    rows = db.execute("SELECT * FROM stocks WHERE user_id = :user", user=session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = :user", user=session["user_id"])[0]['cash']

    # pass a list of lists to the template page, template will iterate thru it to extract data into a displayed table
    total = cash
    stocks = []
    for row in rows:
        stock_info = lookup(row['symbol'])

        #create/append list with all info about the stock
        stocks.append(list((stock_info['symbol'], stock_info['name'], row['shares'], usd(stock_info['price']), usd(stock_info['price'] * row['shares']))))
        total += float(stock_info['price'])

    return render_template("index.html", stocks=stocks, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = lookup(request.form.get("symbol"))['symbol']
        shares = int(request.form.get("shares"))

        if (not symbol) or (not shares):
            return apology("you must fill out both fields")

        if not lookup(symbol):
            return apology("that stock could not be found")
        
        #cash calculate
        price = lookup(symbol)["price"]
        cash = db.execute("SELECT cash FROM users WHERE id = :user", user=session["user_id"])[0]["cash"]
        cash_after = cash - price * float(shares)

        if cash_after < 0:
            return apology("not enough money for this transaction")

        #does user already have stock from this company?
        stock = db.execute("SELECT shares FROM stocks WHERE user_id = :user AND symbol = :symbol", user=session["user_id"], symbol=symbol)

        #insert new row into stock table
        if not stock:
            db.execute("INSERT INTO stocks(user_id, symbol, shares) VALUES (:user, :symbol, :shares)", user=session["user_id"], symbol=symbol, shares=shares)
        
        else: #update row in table
            shares += stock[0]["shares"]
            db.execute("UPDATE stocks SET shares = :shares WHERE user_id = :user AND symbol = :symbol", user=session["user_id"], symbol=symbol, shares=shares)
        #update user's cash
        db.execute("UPDATE users SET cash = :cash WHERE id = :user", cash=cash_after, user=session["user_id"])

        #update history table
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute("INSERT INTO transactions(user_id, symbol, shares, value, time) VALUES (:user, :symbol, :shares, :value, :time)", user=session["user_id"], symbol=symbol, shares=shares, value=usd(price*float(shares)), time=now)
        
        flash("Bought!")
        return redirect("/")
        
    return apology("sorry, something went wrong")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    #try:
    rows = db.execute("SELECT * FROM transactions WHERE user_id = :user", user=session["user_id"])
    transactions = []
    for row in rows:
        stock_inf = lookup(row['symbol'])

        # create a list with info about transaction, append to a list of every stock transaction
        transactions.append(list((stock_inf['symbol'], stock_inf['name'], row['shares'], row['value'], row['time'])))

    return render_template("history.html", transactions=transactions)

    #except:
    #    return apology("sorry, something went wrong")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        session["username"] = request.form.get("username")

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("cannot find that stock")
        return render_template("quoted.html", stock=stock)
    return apology("sorry, something went wrong")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        if not username:
            return apology("your username cannot be blank")
        if len(db.execute("SELECT 1 FROM users WHERE username=?", username)) != 0:
            return apology("sorry, that username is taken")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password)
        if not password:
            return apology("your password cannot be blank")
        elif not confirmation:
            return apology("you must enter your password a second time")
        elif password != confirmation:
            return apology("your passwords must match")
        #password must be at least 5 characters long and contain at least 1 number
        nums_in_pass = 0
        for char in password:
            if char in '1234567890':
                nums_in_pass += 1
        if nums_in_pass < 1 or len(password) < 5:
            return apology("your password must be 5 or more characters long and contain at least 1 number")
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)
        return redirect("/")
    return apology("sorry, something went wrong")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        rows = db.execute("SELECT symbol, shares FROM stocks WHERE user_id = :user", user=session["user_id"])
        stocks = {} #make dict that shows available stocks
        for row in rows:
            stocks[row["symbol"]] = row["shares"]
        return render_template("sell.html", stocks=stocks)
    else:
        shares=int(request.form.get("shares"))
        symbol=request.form.get("symbol")
        price=lookup(symbol)["price"]
        value=price*float(shares)

        shares_before = db.execute("SELECT shares FROM stocks WHERE user_id = :user AND symbol = :symbol", symbol=symbol, user=session["user_id"])[0]['shares']
        shares_after = shares_before - shares

        #if user sold all shares of a stock, delete that stock from stocks table
        if shares_after == 0:
            db.execute("DELETE FROM stocks WHERE user_id = :user AND symbol = :symbol", symbol=symbol, user=session["user_id"])
        #if not own that many shares
        elif shares_after < 0:
            return apology("you don't own that many shares")
        else: #otherwise update w new value
            db.execute("UPDATE stocks SET shares = :shares WHERE user_id = :user AND symbol = :symbol", symbol=symbol, user=session["user_id"], shares=shares_after)

        #calc/update cash
        cash = db.execute("SELECT cash FROM users WHERE id = :user", user=session["user_id"])[0]['cash']
        cash_after = cash + price * float(shares)
        db.execute("UPDATE users SET cash = :cash WHERE id = :user", cash=cash_after, user=session["user_id"])

        #update the history table
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute("INSERT INTO transactions(user_id, symbol, shares, value, time) VALUES (:user, :symbol, :shares, :value, :time)", user=session["user_id"], symbol=symbol, shares=-shares, value=usd(value), time=now)

        #success message & redirect to index
        flash("Sold!")
        return redirect("/")

    return apology("sorry, something went wrong")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
