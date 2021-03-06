import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required,  usd

# Set the date

app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///budget.db")

app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.route("/")
@login_required
def index():
    date = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])

    now = datetime.datetime.now()

    if now.month != date[0]["startmonth"] or now.year != date[0]["startyear"]:
        categories = db.execute("SELECT * FROM categories WHERE user_id = ?", session['user_id'])
        for row in categories:
            db.execute("UPDATE categories SET remainingc = ? WHERE user_id = ? AND cid = ?",
                row["remainingc"] + row["amount"],
                session['user_id'],
                row["cid"])

        db.execute("UPDATE users SET startmonth = ?, startyear = ? WHERE id = ?",
                now.month,
                now.year,
                session['user_id'])


    categories = db.execute("SELECT * FROM categories JOIN users ON users.id = categories.user_id WHERE users.id = ?", session['user_id'])
    if len(categories) > 0:
        categories[0]["remaining"] = categories[0]["budget"]
    for index, row in enumerate(categories):
        categories[0]["remaining"] = categories[0]["remaining"] - categories[index]["amount"]
    return render_template("index.html", categories=categories, date=date)


@app.route("/login", methods=["GET", "POST"])
def login():
    # clear user_id
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()

    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("missing username")
        elif not request.form.get("password"):
            return apology("missing password")
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match")

        try:
            id = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                            request.form.get("username"),
                            generate_password_hash(request.form.get("password")))
        except:
            return apology("username is already taken")

        # Log the user in
        session["user_id"] = id

        flash("Registered!")
        return redirect("/setup")
    else:
        return render_template("register.html")

@app.route("/setup", methods=["GET", "POST"])
@login_required
def setup():
    now = datetime.datetime.now()

    if request.method == "GET":
        return render_template("setup.html")
    if not request.form.get("cash"):
        return apology("Please enter cash amount")
    elif not request.form.get("budgeted"):
        return apology("Please enter your budget amount")

    db.execute("UPDATE users SET cash = ?, budget = ?, startmonth = ?, startyear = ? WHERE id = ?",
                request.form.get("cash"),
                request.form.get("budgeted"),
                now.month,
                now.year,
                session['user_id'])

    return redirect("/categories")


@app.route("/categories", methods=["GET", "POST"])
@login_required
def categories():
    # Check to make sure the form is filled out
    if request.method == "POST":
        if not request.form.get("category"):
            return apology("Please enter a category")
        if not request.form.get("amount"):
            return apology("Please enter an amount")

        db.execute("INSERT INTO categories (category, amount, user_id, remainingc) VALUES (?, ?, ?, ?)",
                    request.form.get("category"),
                    request.form.get("amount"),
                    session['user_id'],
                    request.form.get("amount"))
    categories = db.execute("SELECT * FROM categories JOIN users ON users.id = categories.user_id WHERE users.id = ?", session['user_id'])
    if len(categories) > 0:
        categories[0]["remaining"] = categories[0]["budget"]
        for index, row in enumerate(categories):
            categories[0]["remaining"] = categories[0]["remaining"] - categories[index]["amount"]
    return render_template("categories.html", categories=categories)


@app.route("/transactions", methods=["GET", "POST"])
@login_required
def transactions():
    # Check to make sure the form is filled out
    if request.method == "POST":
        if not request.form.get("transaction"):
            return apology("Please enter a transaction")
        if not request.form.get("amount"):
            return apology("Please enter an amount")
        if not request.form.get("date"):
            return apology("Please enter an date")
        if not request.form.get("category"):
            return apology("Please enter an category")

        # edit transactions
        db.execute("INSERT INTO transactions (category, amount, user_id, date, name) VALUES (?, ?, ?, ?, ?)",
                    request.form.get("category"),
                    request.form.get("amount"),
                    session['user_id'],
                    request.form.get("date"),
                    request.form.get("transaction"))

        # Update the Categories
        categories = db.execute("SELECT remainingc FROM categories WHERE user_id = ? AND category = ?",
                                session['user_id'],
                                request.form.get("category"))
        if len(categories) == 0:
            return apology("Please Create this category first")
        categories[0]["remainingc"] = categories[0]["remainingc"] - float(request.form.get("amount"))
        db.execute("UPDATE categories SET remainingc = ? WHERE user_id = ? AND category = ?",
                    categories[0]["remainingc"],
                    session['user_id'],
                    request.form.get("category"))

        # Update the User
        cash = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
        cash[0]["cash"] = cash[0]["cash"] - float(request.form.get("amount"))
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                    cash[0]["cash"],
                    session['user_id'])
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session['user_id'])
    users = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
    return render_template("transactions.html", transactions=transactions, users=users)


@app.route("/view", methods=["GET", "POST"])
@login_required
def view():
    if not request.form.get("month"):
        return apology("Please enter a month")
    if not request.form.get("year"):
        return apology("Please enter a year")

    # Format the date to search database
    month = request.form.get("month")
    if len(month) < 2:
        month = '0' + month
    date = request.form.get("year") + '-' + month

    # Filter the transactions
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? AND date LIKE ?", session['user_id'], date + '%')
    users = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
    return render_template("transactions.html", transactions=transactions, date=date, users=users)


@app.route("/edit_transactions", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == "GET":
        edit = request.args.get('edit')
        return render_template("edit_transactions.html", edit = edit)

    if request.method == "POST":
        if request.form.get("transaction"):
            db.execute("UPDATE transactions SET name = ? WHERE user_id = ? AND idt = ?",
                request.form.get("transaction"),
                session['user_id'],
                request.form.get("edit"))
        if request.form.get("amount"):
            transactions = db.execute("SELECT * FROM transactions JOIN users ON users.id = transactions.user_id WHERE users.id = ? AND idt = ?", session['user_id'], request.form.get("edit"))
            categories = db.execute("SELECT * FROM categories WHERE user_id = ? AND category = ?",
                                    session['user_id'],
                                    transactions[0]["category"])
            difference = transactions[0]["amount"] - float(request.form.get("amount"))
            cash = transactions[0]["cash"] + difference
            change = categories[0]["amount"] - difference
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session['user_id'])
            db.execute("UPDATE transactions SET amount = ? WHERE user_id = ? AND idt = ?",
                float(request.form.get("amount")),
                session['user_id'],
                request.form.get("edit"))
            db.execute("UPDATE categories SET remainingc = ? WHERE user_id = ? AND category = ?",
                categories[0]["remainingc"] + difference,
                session['user_id'],
                transactions[0]["category"])
        if request.form.get("date"):
            db.execute("UPDATE transactions SET date = ? WHERE user_id = ? AND idt = ?",
                request.form.get("date"),
                session['user_id'],
                request.form.get("edit"))
        if request.form.get("category"):
            db.execute("UPDATE transactions SET category = ? WHERE user_id = ? AND idt = ?",
                request.form.get("category"),
                session['user_id'],
                request.form.get("edit"))
        return redirect("/transactions")


@app.route("/edit_categories", methods=["GET", "POST"])
@login_required
def edit_categories():
    if request.method == "GET":
        edit = request.args.get('edit')
        return render_template("edit_categories.html", edit = edit)

    if request.method == "POST":
        if request.form.get("category"):
            db.execute("UPDATE categories SET category = ? WHERE user_id = ? AND cid = ?",
                request.form.get("category"),
                session['user_id'],
                request.form.get("edit"))
        if request.form.get("amount"):
            categories = db.execute("SELECT * FROM categories WHERE user_id = ? AND cid = ?", session['user_id'], request.form.get("edit"))
            difference = categories[0]["amount"] - float(request.form.get("amount"))
            categories[0]["remainingc"] = categories[0]["remainingc"] - difference
            db.execute("UPDATE categories SET amount = ?, remainingc = ? WHERE user_id = ? AND cid = ?",
                request.form.get("amount"),
                categories[0]["remainingc"],
                session['user_id'],
                request.form.get("edit"))
        return redirect("/categories")