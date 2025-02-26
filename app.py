from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import settings
from datetime import datetime

app = Flask(__name__)
app.config.from_object(settings)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def init_db():
    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          first_name TEXT,
                          last_name TEXT,
                          email TEXT UNIQUE,
                          password TEXT,
                          role TEXT DEFAULT 'user')''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS posts (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          title TEXT,
                          content TEXT,
                          author_id INTEGER,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          FOREIGN KEY (author_id) REFERENCES users (id))''')
        conn.commit()
def update_db():
    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            conn.commit()
        except sqlite3.OperationalError:
            pass  


class User(UserMixin):
    def __init__(self, id, first_name, last_name, email, role):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.role = role

    @login_manager.user_loader
    def load_user(user_id):
        with sqlite3.connect('wezoll.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, first_name, last_name, email, role FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
        if user:
            return User(*user)
        return None

@app.route('/')
def home():
    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT posts.id, posts.title, posts.content, users.first_name, users.last_name, posts.created_at FROM posts JOIN users ON posts.author_id = users.id ORDER BY posts.created_at DESC")
        posts = cursor.fetchall()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        role = 'admin' if email == 'wezoll69@gmail.com' else 'user'

        with sqlite3.connect('wezoll.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)", 
                               (first_name, last_name, email, hashed_password, role))
                conn.commit()
                flash('Регистрация успешна! Теперь вы можете войти.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Этот email уже зарегистрирован.', 'danger')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect('wezoll.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, first_name, last_name, email, password, role FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user[4], password):
                login_user(User(*user[:5]))
                flash('Вы успешно вошли!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Неверный email или пароль', 'danger')
    return render_template('login.html')

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        with sqlite3.connect('wezoll.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)", (title, content, current_user.id))
            conn.commit()
        flash('Пост успешно создан!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html')

@app.route('/post/<int:post_id>')
def view_post(post_id):
    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT posts.id, posts.title, posts.content, users.first_name, users.last_name, posts.created_at FROM posts JOIN users ON posts.author_id = users.id WHERE posts.id = ?", (post_id,))
        post = cursor.fetchone()
    return render_template('view_post.html', post=post)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, content, author_id FROM posts WHERE id = ?", (post_id,))
        post = cursor.fetchone()

    if not post or (post[3] != current_user.id):
        flash('У вас нет прав на редактирование этого поста.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        with sqlite3.connect('wezoll.db') as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE posts SET title = ?, content = ? WHERE id = ?", (title, content, post_id))
            conn.commit()
        flash('Пост успешно обновлен!', 'success')
        return redirect(url_for('view_post', post_id=post_id))

    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT author_id FROM posts WHERE id = ?", (post_id,))
        post = cursor.fetchone()

    if not post or (post[0] != current_user.id and current_user.role != 'admin'):
        flash('У вас нет прав на удаление этого поста.', 'danger')
        return redirect(url_for('home'))

    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        conn.commit()

    flash('Пост успешно удалён!', 'success')
    return redirect(url_for('home'))


@app.route('/profile')
@login_required
def profile():
    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, content, created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC", (current_user.id,))
        posts = cursor.fetchall()
    return render_template('profile.html', user=current_user, posts=posts)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect('wezoll.db') as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?", (first_name, last_name, email, current_user.id))
            if password:
                hashed_password = generate_password_hash(password)
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, current_user.id))
            conn.commit()
        flash('Профиль обновлён!', 'success')
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', user=current_user)

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('home'))

    with sqlite3.connect('wezoll.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, first_name, last_name, email, role FROM users ORDER BY first_name")
        users = cursor.fetchall()
    return render_template('users.html', users=users)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    update_db()
    app.run(debug=True)
