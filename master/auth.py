# master/auth.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash

from .models import db, User, Setting
from .app import SetupForm, LoginForm # Import forms from app.py or a forms.py

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    # Check if setup is needed before allowing login attempt
    admin_exists = User.query.first() is not None
    if not admin_exists and request.method == 'POST':
         flash("系统尚未设置，请先完成首次设置。", "warning")
         return redirect(url_for('auth.setup'))
    elif not admin_exists and request.method == 'GET':
         # Redirect directly to setup if no admin exists
         return redirect(url_for('auth.setup'))


    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user and user.check_password(form.password.data):
            login_user(user) # Add remember=form.remember_me.data if using remember me
            flash('登录成功！', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('用户名或密码无效。', 'danger')
    return render_template('login.html', form=form, admin_exists=admin_exists)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功退出登录。', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    # Prevent access if already set up
    if User.query.first() is not None:
        flash("系统已经设置过了。", "warning")
        return redirect(url_for('auth.login'))

    form = SetupForm()
    if form.validate_on_submit():
        # Check again just in case of race condition
        if User.query.first() is not None:
             flash("设置似乎刚刚已被其他人完成。", "warning")
             return redirect(url_for('auth.login'))

        try:
            # Create admin user
            hashed_password = generate_password_hash(form.password.data)
            admin_user = User(username=form.username.data, password_hash=hashed_password)
            db.session.add(admin_user)

            # Create initial settings
            settings = Setting(
                backup_base_path=form.backup_base_path.data,
                backup_ssh_user=form.backup_ssh_user.data
                # Add defaults for other settings if needed
            )
            db.session.add(settings)

            # Commit changes
            db.session.commit()

            # Log in the newly created admin user? Or redirect to login?
            # Let's redirect to login for clarity.
            flash('设置成功！现在可以使用您的管理员账户登录。', 'success')
            current_app.logger.info("Initial setup completed successfully.")
            return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during initial setup: {e}", exc_info=True)
            flash(f'设置过程中发生错误: {e}', 'danger')

    return render_template('setup.html', form=form)
