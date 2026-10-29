# 导入操作系统接口模块，用于访问环境变量等系统功能
import csv
import io
import os
import time
import re  # 新增：用于正则表达式验证
from functools import wraps
# 从flask导入核心功能类和方法
from flask import Flask, render_template, redirect, url_for, request, flash, Response, abort
# 导入Flask-SQLAlchemy扩展，用于数据库操作
# from flask_sqlalchemy import SQLAlchemy
# 导入Flask-Login扩展，用于用户认证管理
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
#from flask_sqlalchemy import Pagination
from flask_sqlalchemy.pagination import Pagination
# 导入Flask-WTF扩展，用于表单处理
from flask_wtf import FlaskForm
# 从WTForms导入表单字段类
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField
# 从WTForms导入验证器
from wtforms.validators import DataRequired, Length, ValidationError  # 新增 ValidationError
# 导入datetime模块，用于处理日期和时间
from datetime import datetime, timedelta
# 导入dotenv模块，用于从.env文件加载环境变量
from dotenv import load_dotenv
# 从models模块导入数据库模型类
from models import db, User, FaultReport
from csv_safety import csv_safe
# 2026-10-07 新增：口令哈希校验/生成 + 登录失败限流
import hmac
from werkzeug.security import generate_password_hash, check_password_hash
from login_guard import LoginGuard
#####统计加的
from sqlalchemy import func, extract
from collections import defaultdict

# 加载.env文件中的环境变量
load_dotenv()

# 创建Flask应用实例
app = Flask(__name__)
# 设置应用密钥，用于会话安全（实际部署时应使用强密钥）
# 2026-10-07 修复：原兜底值 'your-secret-key' 是公开常量（app.py 顶部已
# load_dotenv()，正常有值）⇒ 改 fail-closed，缺配置时拒绝启动而非静默降级。
_signal_secret = (os.getenv('SECRET_KEY') or '').strip()
if not _signal_secret or _signal_secret in ('your-secret-key', 'your-secret-key-here'):
    raise RuntimeError('SECRET_KEY 未配置或仍为占位常量，拒绝启动（signal_fault）')
app.config['SECRET_KEY'] = _signal_secret
# 配置数据库连接URI（支持从环境变量获取）
_signal_db_url = (os.getenv('DATABASE_URL') or '').strip()
if not _signal_db_url:
    raise RuntimeError('DATABASE_URL 未配置，拒绝启动（signal_fault）')
app.config['SQLALCHEMY_DATABASE_URI'] = _signal_db_url
# 禁用SQLAlchemy的修改追踪功能，提高性能
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
# 2026-10-07：恢复真实客户端 IP。.80 nginx 写入 X-Forwarded-For（单值、覆盖写），
# 经 frp L4 隧道直达本进程；gunicorn 不解析 XFF ⇒ 用 ProxyFix 取回 1 跳信任。
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'self'; base-uri 'self'; "
        "form-action 'self'; object-src 'none'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=()'
    )
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    return response


# 初始化SQLAlchemy数据库扩展
db.init_app(app)
# 创建登录管理器实例
login_manager = LoginManager(app)
# 设置登录视图的端点名称（未登录用户重定向到该端点）
login_manager.login_view = 'login'

# 登录失败限流（2026-10-07 新增）：服务端、账号级、跨进程/跨 worker 共享。
# 本架构下 frp 为 L4 透传，服务端拿不到真实客户端 IP，按 IP 限流无意义。
login_guard = LoginGuard('/var/lib/login_guard/signal_fault.db',
                         max_fails=5, window=300, name='signal_fault')


# 登录表单定义
class LoginForm(FlaskForm):
    # 用户名输入字段（必填，长度3-50字符）
    username = StringField('用户名', validators=[DataRequired(), Length(min=3, max=50)])
    # 密码输入字段（必填，最小长度6字符）
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    # 提交按钮
    submit = SubmitField('登录')


##报告表单
class ReportForm(FlaskForm):
    # 新增区域字段
    region = SelectField('区域', choices=[
        ('汶上县', '汶上县'),
        ('泗水县', '泗水县'),
        ('嘉祥县', '嘉祥县'),
        ('邹城市', '邹城市'),
        ('金乡县', '金乡县'),
        ('鱼台县', '鱼台县'),
        ('经开区', '经开区'),
        ('高新区', '高新区'),
        ('任城区', '任城区'),
        ('其他', '其他')
    ], validators=[DataRequired()])
    # 路口名称字段
    junction = StringField('路口名称', validators=[DataRequired(), Length(max=100)])
    # 项目名称字段
    project = StringField('项目名称', validators=[DataRequired(), Length(max=100)])
    # 信号机编号字段
    signal_id = StringField('信号机编号', validators=[DataRequired(), Length(max=50)])
    # 新增信号机程序版本字段
    signal_version = StringField('信号机程序版本', validators=[DataRequired(), Length(max=50)])
    # 新增故障发生时间字段
    fault_time = StringField('故障发生时间 (YYYY-MM-DD HH:MM)', validators=[DataRequired()])
    # 故障现象文本区域
    fault_phenomenon = TextAreaField('故障日志及现场现象', validators=[DataRequired()])
    # 解决方案文本区域
    solution = TextAreaField('现场处理办法')
    # 故障等级下拉选择
    fault_level = SelectField('故障等级', choices=[
        ('1', '1级 线路故障'),
        ('2', '2级 灯具故障'),
        ('3', '3级 信号机硬件故障'),
        ('4', '4级 信号机软件故障'),
        ('5', '5级 信号机软硬件故障')
    ], validators=[DataRequired()])
    # 提交按钮
    submit = SubmitField('提交报告')

    # 新增：路口名称格式验证
    def validate_junction(self, field):
        # 放宽规则：允许使用"街"、"大道"等后缀，但也可省略后缀
        pattern = r'^[\u4e00-\u9fa5A-Za-z0-9]+(?:路|街|大道|巷|道)?-[\u4e00-\u9fa5A-Za-z0-9]+(?:路|街|大道|巷|道)?$'
        if not re.match(pattern, field.data):
            raise ValidationError('路口名称格式错误！请使用"东西方向路名-南北方向路名"格式，例如：太白路-火炬路 或 G105-S324')
    # 更新信号机编号格式验证
    def validate_signal_id(self, field):
        # 新正则表达式：匹配 KWD02A-四位数字-四位数字-V1 或 KWD02A-四位数字-四位数字-V2
        pattern = r'^KWD02A-\d{4}-\d{4}-V[12]$'
        if not re.match(pattern, field.data):
            raise ValidationError('信号机编号格式错误！请使用"KWD02A-1234-5678-V1"或"-V2"')


# 查询表单定义 - 修改后
class QueryForm(FlaskForm):
    # 新增区域查询字段
    region = SelectField('区域', choices=[
        ('', '所有区域'),
        ('汶上县', '汶上县'),
        ('泗水县', '泗水县'),
        ('嘉祥县', '嘉祥县'),
        ('邹城市', '邹城市'),
        ('金乡县', '金乡县'),
        ('鱼台县', '鱼台县'),
        ('经开区', '经开区'),
        ('高新区', '高新区'),
        ('任城区', '任城区'),
        ('其他', '其他')
    ])
    # 路口名称查询字段
    junction = StringField('路口名称')
    # 项目名称查询字段
    project = StringField('项目名称')
    # 信号机编号查询字段
    signal_id = StringField('信号机编号')
    # 新增信号机程序版本查询字段
    signal_version = StringField('信号机程序版本')
    # 提交人查询字段
    reporter = StringField('提交人')
    # 故障等级查询下拉框
    fault_level = SelectField('故障等级', choices=[
        ('', '所有等级'),
        ('1', '1级 线路故障'),
        ('2', '2级 灯具故障'),
        ('3', '3级 信号机硬件故障'),
        ('4', '4级 信号机软件故障'),
        ('5', '5级 信号机软硬件故障')
    ])
    # 开始日期查询字段
    start_date = StringField('开始日期 (YYYY-MM-DD)')
    # 结束日期查询字段
    end_date = StringField('结束日期 (YYYY-MM-DD)')
    # 查询按钮
    submit = SubmitField('查询')
    # 新增导出按钮
    export = SubmitField('导出CSV')


# 用户加载回调函数 - Flask-Login要求
@login_manager.user_loader
def load_user(user_id):
    # 根据用户ID从数据库加载用户对象
    return User.query.get(int(user_id))


# 数据库初始化函数
def initialize_database():
    # 使用应用上下文确保在正确的环境中操作
    with app.app_context():
        # 创建所有数据库表
        db.create_all()
        # 检查管理员用户是否存在
        if not User.query.filter_by(username='admin').first():
            # 创建初始管理员用户（实际应用中应使用哈希密码）
            admin = User(username='admin',
                         password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                         fullname='系统管理员', role='admin', must_change_password=True)
            db.session.add(admin)
            db.session.commit()


# 根路由 - 重定向到登录页面
@app.route('/')
def home():
    return redirect(url_for('login'))


# 登录路由 - 支持GET/POST方法
def _verify_password(stored, raw):
    """校验口令：哈希走 werkzeug，历史明文走常量时间比较（迁移期兜底）。"""
    stored = stored or ''
    if stored.startswith(('pbkdf2:', 'scrypt:')):
        return check_password_hash(stored, raw or '')
    return hmac.compare_digest(stored, raw or '')


def _rehash_if_plaintext(user, raw):
    """旧明文口令在登录成功后自愈为哈希（幂等）。"""
    if user is None:
        return
    if not (user.password or '').startswith(('pbkdf2:', 'scrypt:')):
        user.password = generate_password_hash(raw, method='pbkdf2:sha256')
        db.session.commit()


def _csrf_expired(form):
    """表单是否【仅因 CSRF 令牌】校验失败（区别于字段本身校验不过）。

    ⚠️ 必须在 form.validate() / validate_on_submit() **之后**调用：WTForms 的
    field.errors 是校验过程的产物，未校验时恒为空。（v1 补丁把判定放在校验
    之前 ⇒ 守卫永不触发，已由 repair_signal_csrf.py 原地修正。）

    2026-10-07 修复：signal_fault 用表单级 CSRF（FlaskForm.validate_on_submit），
    令牌缺失/过期时 validate() 直接返回 False 且**不产生任何提示** ⇒ 用户点
    “登录”后页面原样重刷，看起来像“点了没反应”“密码明明对却登不上”。
    WTF_CSRF_TIME_LIMIT 默认 3600 秒：在登录页停留超过 1 小时再提交必然命中。
    """
    return bool('csrf_token' in (getattr(form, 'errors', None) or {}))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    lockout_msg = None
    _submitted = form.validate_on_submit()
    if not _submitted and _csrf_expired(form):
        flash('页面已过期（会话或校验令牌失效），请刷新后重新提交', 'warning')
        return render_template('login.html', form=LoginForm()), 400
    if _submitted:
        username = form.username.data
        locked, wait = login_guard.is_locked(username)
        # 查询用户是否存在
        user = User.query.filter_by(username=username).first()
        # 被禁用账号直接拒绝登录（不计入失败次数，避免误判锁定）
        if user and getattr(user, 'disabled', False):
            flash('该账号已被禁用，请联系管理员', 'danger')
            return render_template('login.html', form=form)
        # 验证用户凭证（2026-10-07：明文比较 → werkzeug 哈希校验）
        if user and _verify_password(user.password, form.password.data):
            _rehash_if_plaintext(user, form.password.data)
            login_guard.reset(username)
            login_user(user)  # Flask-Login登录操作
            if getattr(user, 'must_change_password', False):
                flash('首次登录，请先修改密码', 'warning')
                return redirect(url_for('change_password'))
            flash('登录成功！', 'success')
            return redirect(url_for('report'))  # 登录成功后跳转到报告页面
        if locked:
            lockout_msg = f'登录失败次数过多，请 {wait} 秒后再试'
            return render_template('login.html', form=form, lockout_msg=lockout_msg), 429
        login_guard.record_failure(username)
        left = login_guard.remaining_attempts(username)
        if left > 0:
            flash(f'用户名或密码错误！还有 {left} 次尝试机会', 'danger')
        else:
            flash('登录失败次数过多，请 5 分钟后再试', 'danger')
    return render_template('login.html', form=form)


# ===== 首登强制改密（2026-10-07 新增）=====
class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('当前密码', validators=[DataRequired(), Length(min=6, max=128)])
    new_password = PasswordField('新密码', validators=[DataRequired(), Length(min=12, max=128)])
    confirm_password = PasswordField('确认新密码', validators=[DataRequired(), Length(min=12, max=128)])
    submit = SubmitField('修改密码')


def _password_policy_error(new_password, old_password):
    if new_password == old_password:
        return '新密码不能与当前密码相同'
    if len(new_password or '') < 12:
        return '新密码长度不能少于12位'
    if not re.search(r'[A-Za-z]', new_password) or not re.search(r'\d', new_password):
        return '新密码必须同时包含字母和数字'
    return None


@app.before_request
def _enforce_password_change():
    """未改初始密码的登录用户，除改密/登出/静态资源外一律引导到改密页。"""
    if not current_user.is_authenticated:
        return None
    if not getattr(current_user, 'must_change_password', False):
        return None
    if request.endpoint in ('change_password', 'logout', 'static', 'login'):
        return None
    return redirect(url_for('change_password'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    scope = 'chpw:%s' % (getattr(current_user, 'username', '') or '')
    _submitted = form.validate_on_submit()
    if not _submitted and _csrf_expired(form):
        flash('页面已过期（会话或校验令牌失效），请刷新后重新提交', 'warning')
        return render_template('change_password.html', form=ChangePasswordForm()), 400
    if _submitted:
        locked, wait = login_guard.is_locked(scope)
        if locked:
            flash(f'操作过于频繁，请 {wait} 秒后再试', 'danger')
            return render_template('change_password.html', form=form), 429
        if not _verify_password(current_user.password, form.old_password.data):
            login_guard.record_failure(scope)
            flash('当前密码不正确', 'danger')
            return render_template('change_password.html', form=form)
        if form.new_password.data != form.confirm_password.data:
            flash('两次输入的新密码不一致', 'danger')
            return render_template('change_password.html', form=form)
        err = _password_policy_error(form.new_password.data, form.old_password.data)
        if err:
            flash(err, 'danger')
            return render_template('change_password.html', form=form)
        current_user.password = generate_password_hash(form.new_password.data,
                                                       method='pbkdf2:sha256')
        current_user.must_change_password = False
        db.session.commit()
        login_guard.reset(scope)
        login_guard.reset(current_user.username)
        flash('密码修改成功！', 'success')
        return redirect(url_for('report'))
    return render_template('change_password.html', form=form)


# ===== 用户管理（2026-10-29 新增，参考 labormanagement）=====
def admin_required(view):
    """仅 role='admin' 可访问；非管理员返回 403。"""
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if getattr(current_user, 'role', 'user') != 'admin':
            abort(403)
        return view(*args, **kwargs)
    return wrapper


class AddUserForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=3, max=50)])
    fullname = StringField('姓名', validators=[DataRequired(), Length(min=2, max=100)])
    password = PasswordField('初始密码', validators=[DataRequired(), Length(min=12, max=128)])
    role = SelectField('角色', choices=[('user', '普通用户'), ('admin', '管理员')],
                       validators=[DataRequired()])
    submit = SubmitField('添加用户')


class EditUserForm(FlaskForm):
    fullname = StringField('姓名', validators=[DataRequired(), Length(min=2, max=100)])
    role = SelectField('角色', choices=[('user', '普通用户'), ('admin', '管理员')],
                       validators=[DataRequired()])
    submit = SubmitField('保存修改')


class ResetUserPasswordForm(FlaskForm):
    new_password = PasswordField('新密码', validators=[DataRequired(), Length(min=12, max=128)])
    submit = SubmitField('重置密码')


class ConfirmForm(FlaskForm):
    """仅承载 CSRF 的空表单，用于删除等确认操作。"""
    submit = SubmitField('确认')


def _admin_count():
    return User.query.filter_by(role='admin').count()


@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.id.asc()).all()
    return render_template('users.html',
                           users=users,
                           add_form=AddUserForm(),
                           edit_form=EditUserForm(),
                           reset_form=ResetUserPasswordForm(),
                           confirm_form=ConfirmForm())


@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    form = AddUserForm()
    if not form.validate_on_submit():
        for errs in form.errors.values():
            for e in errs:
                flash(e, 'danger')
        return redirect(url_for('admin_users'))

    username = form.username.data.strip()
    if not re.match(r'^[A-Za-z0-9_\-]{3,50}$', username):
        flash('用户名仅允许字母、数字、下划线、中划线，长度 3-50', 'danger')
        return redirect(url_for('admin_users'))

    if User.query.filter_by(username=username).first():
        flash(f'用户名 {username} 已存在', 'danger')
        return redirect(url_for('admin_users'))

    err = _password_policy_error(form.password.data, '')
    if err:
        flash(err, 'danger')
        return redirect(url_for('admin_users'))

    new_user = User(
        username=username,
        password=generate_password_hash(form.password.data, method='pbkdf2:sha256'),
        fullname=form.fullname.data.strip(),
        role=form.role.data,
        must_change_password=True,  # 首次登录强制改密
    )
    db.session.add(new_user)
    db.session.commit()
    flash(f'用户 {username} 添加成功，首次登录需修改密码', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm()
    if not form.validate_on_submit():
        for errs in form.errors.values():
            for e in errs:
                flash(e, 'danger')
        return redirect(url_for('admin_users'))

    # 防止把自己降级导致系统失去管理员
    if user.id == current_user.id and form.role.data != 'admin':
        flash('不能取消自己的管理员角色', 'danger')
        return redirect(url_for('admin_users'))
    if user.role == 'admin' and form.role.data != 'admin' and _admin_count() <= 1:
        flash('系统至少保留一名管理员', 'danger')
        return redirect(url_for('admin_users'))

    user.fullname = form.fullname.data.strip()
    user.role = form.role.data
    db.session.commit()
    flash(f'用户 {user.username} 已更新', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    form = ResetUserPasswordForm()
    if not form.validate_on_submit():
        for errs in form.errors.values():
            for e in errs:
                flash(e, 'danger')
        return redirect(url_for('admin_users'))

    err = _password_policy_error(form.new_password.data, '')
    if err:
        flash(err, 'danger')
        return redirect(url_for('admin_users'))

    user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
    user.must_change_password = True  # 重置后强制用户下次登录改密
    db.session.commit()
    # 重置对应账号的登录失败计数
    login_guard.reset(user.username)
    flash(f'用户 {user.username} 密码已重置，下次登录需修改', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    form = ConfirmForm()
    if not form.validate_on_submit():
        flash('请求校验失败，请重试', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('不能删除当前登录账号', 'danger')
        return redirect(url_for('admin_users'))
    if user.role == 'admin' and _admin_count() <= 1:
        flash('系统至少保留一名管理员', 'danger')
        return redirect(url_for('admin_users'))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'用户 {username} 已删除', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/toggle-disable', methods=['POST'])
@admin_required
def admin_toggle_disable(user_id):
    form = ConfirmForm()
    if not form.validate_on_submit():
        flash('请求校验失败，请重试', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('不能禁用当前登录账号', 'danger')
        return redirect(url_for('admin_users'))

    user.disabled = not user.disabled
    db.session.commit()
    action = '禁用' if user.disabled else '启用'
    flash(f'已{action}用户 {user.username}', 'success')
    return redirect(url_for('admin_users'))


# 登出路由 - 需要登录
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Flask-Login登出操作
    flash('您已成功登出。', 'success')
    return redirect(url_for('login'))


# 故障报告路由 - 支持GET/POST，需要登录 - 修改后
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    form = ReportForm()
    _submitted = form.validate_on_submit()
    if not _submitted and _csrf_expired(form):
        flash('页面已过期（会话或校验令牌失效），请刷新后重新提交', 'warning')
        return render_template('report.html', form=ReportForm()), 400
    if _submitted:
        try:
            # 将字符串转换为datetime对象
            fault_time = datetime.strptime(form.fault_time.data, '%Y-%m-%d %H:%M')
        except ValueError:
            flash('故障发生时间格式错误，请使用YYYY-MM-DD HH:MM格式', 'danger')
            return render_template('report.html', form=form)

        # 创建故障报告对象
        report = FaultReport(
            region=form.region.data,
            junction=form.junction.data,
            project=form.project.data,
            signal_id=form.signal_id.data,
            signal_version=form.signal_version.data,
            fault_time=fault_time,
            fault_phenomenon=form.fault_phenomenon.data,
            solution=form.solution.data,
            fault_level=form.fault_level.data,
            reporter=current_user.fullname  # 使用当前用户全名作为报告人
        )
        db.session.add(report)
        db.session.commit()
        flash('故障报告提交成功！', 'success')
        return redirect(url_for('report'))  # 提交成功后刷新页面
    return render_template('report.html', form=form)


# 查询路由 - 支持GET/POST，需要登录，实现分页功能 - 修改后
@app.route('/query', methods=['GET', 'POST'])
@login_required
def query():
    start_time = time.time()  # 记录开始时间

    form = QueryForm()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    is_export = request.args.get('export') == 'true' or (request.method == 'POST' and form.export.data)

    # 获取所有查询参数（用于表单初始化和分页链接）
    query_params = request.args.copy().to_dict()

    # 检查是否有查询参数（排除分页参数）
    has_query_params = any(param in query_params for param in [
        'region', 'junction', 'project', 'signal_id',
        'signal_version', 'reporter', 'fault_level',
        'start_date', 'end_date'
    ])

    # 处理导出请求（优先处理）
    if is_export:
        # 构建查询（与下面相同的查询逻辑）
        query = build_query(query_params)
        return export_to_csv(query)

    # 构建查询
    query = build_query(query_params)

    # 执行分页查询
    results = query.order_by(FaultReport.report_time.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    # 准备分页链接参数（移除page和export）
    url_args = query_params.copy()
    if 'page' in url_args:
        del url_args['page']
    if 'export' in url_args:
        del url_args['export']

    # 无结果提示
    if not results.items:
        flash('没有找到匹配的记录。', 'info')

    # 在返回响应前添加日志
    elapsed = time.time() - start_time
    app.logger.info(f"查询执行时间: {elapsed:.3f} 秒, 总记录数: {results.total}")

    return render_template('query.html', form=form, results=results, url_args=url_args)


def build_query(params):
    """根据查询参数构建查询"""
    query = FaultReport.query

    # 区域查询
    if params.get('region'):
        query = query.filter(FaultReport.region == params['region'])

    # 路口名称查询 - 使用 startswith 代替 like
    if params.get('junction'):
        # 修改前: query = query.filter(FaultReport.junction.like(f"%{params['junction']}%"))
        # 修改后:
        query = query.filter(FaultReport.junction.startswith(params['junction']))

    # 项目名称查询 - 使用 startswith 代替 like
    if params.get('project'):
        # 修改前: query = query.filter(FaultReport.project.like(f"%{params['project']}%"))
        # 修改后:
        query = query.filter(FaultReport.project.startswith(params['project']))

    # 信号机编号查询 - 使用 startswith 代替 like
    if params.get('signal_id'):
        # 修改前: query = query.filter(FaultReport.signal_id.like(f"%{params['signal_id']}%"))
        # 修改后:
        query = query.filter(FaultReport.signal_id.startswith(params['signal_id']))

    # 信号机版本查询 - 使用 startswith 代替 like
    if params.get('signal_version'):
        # 修改前: query = query.filter(FaultReport.signal_version.like(f"%{params['signal_version']}%"))
        # 修改后:
        query = query.filter(FaultReport.signal_version.startswith(params['signal_version']))

    # 提交人查询 - 使用 startswith 代替 like
    if params.get('reporter'):
        # 修改前: query = query.filter(FaultReport.reporter.like(f"%{params['reporter']}%"))
        # 修改后:
        query = query.filter(FaultReport.reporter.startswith(params['reporter']))

    # 故障等级查询
    if params.get('fault_level'):
        query = query.filter(FaultReport.fault_level == params['fault_level'])

    # 日期范围查询
    if params.get('start_date'):
        try:
            start_date = datetime.strptime(params['start_date'], '%Y-%m-%d')
            query = query.filter(FaultReport.report_time >= start_date)
        except ValueError:
            flash('开始日期格式错误，请使用YYYY-MM-DD格式', 'warning')

    if params.get('end_date'):
        try:
            end_date = datetime.strptime(params['end_date'], '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(FaultReport.report_time < end_date)
        except ValueError:
            flash('结束日期格式错误，请使用YYYY-MM-DD格式', 'warning')

    return query


# 导出为CSV文件

def export_to_csv(query):
    """流式导出CSV，避免内存溢出"""

    def generate():
        # 手动创建应用上下文
        with app.app_context():
            # 缓冲区
            buffer = io.StringIO()
            writer = csv.writer(buffer)

            # 写入表头
            writer.writerow([
                '序号', '区域', '路口名称', '项目名称', '信号机编号',
                '信号机程序版本', '故障发生时间', '故障日志及现场现象', '现场处理办法',
                '故障等级', '提交人', '提交时间'
            ])
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

            # 分批处理（每次500条）
            batch_size = 500
            offset = 0

            # 在应用上下文中计算总数
            total = query.count()

            while offset < total:
                # 获取当前批次的数据
                reports = query.order_by(FaultReport.report_time.desc()).offset(offset).limit(batch_size).all()

                for idx, report in enumerate(reports, offset + 1):
                    writer.writerow([
                        idx,
                        csv_safe(report.region),
                        csv_safe(report.junction),
                        csv_safe(report.project),
                        csv_safe(report.signal_id),
                        csv_safe(report.signal_version),
                        report.fault_time.strftime('%Y-%m-%d %H:%M'),
                        csv_safe(report.fault_phenomenon),
                        csv_safe(report.solution),
                        get_fault_level_display(report.fault_level),
                        csv_safe(report.reporter),
                        report.report_time.strftime('%Y-%m-%d %H:%M')
                    ])
                    # 每写一行就清空缓冲区并发送，避免内存占用过大
                    yield buffer.getvalue()
                    buffer.seek(0)
                    buffer.truncate(0)

                offset += batch_size

    # 创建响应
    today = datetime.now().strftime('%Y%m%d')
    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=fault_reports_{today}.csv"}
    )


# 统计路由
# 在路由部分添加统计路由
@app.route('/statistics')
@login_required
def statistics():
    # 按区域统计
    region_stats = db.session.query(
        FaultReport.region,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.region).all()

    # 按路口名称统计（取前10）
    junction_stats = db.session.query(
        FaultReport.junction,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.junction).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 按信号机编号统计（取前10）
    signal_stats = db.session.query(
        FaultReport.signal_id,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.signal_id).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 按故障等级统计
    level_stats = db.session.query(
        FaultReport.fault_level,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.fault_level).order_by(FaultReport.fault_level).all()

    # 按故障发生月份统计（最近12个月）
    end_date = datetime.now()
    start_date = end_date - timedelta(days=365)

    monthly_stats = db.session.query(
        func.extract('year', FaultReport.fault_time).label('year'),
        func.extract('month', FaultReport.fault_time).label('month'),
        func.count(FaultReport.id).label('count')
    ).filter(FaultReport.fault_time >= start_date).group_by('year', 'month').order_by('year', 'month').all()

    # 格式化月度数据
    monthly_data = []
    for year, month, count in monthly_stats:
        monthly_data.append({
            'label': f"{int(year)}年{int(month)}月",
            'count': count
        })

    # 按提交人统计（取前10）
    reporter_stats = db.session.query(
        FaultReport.reporter,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.reporter).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 按项目名称统计（取前10）
    project_stats = db.session.query(
        FaultReport.project,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.project).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 故障等级映射关系
    level_mapping = {
        '1': '1级 线路故障',
        '2': '2级 灯具故障',
        '3': '3级 信号机硬件故障',
        '4': '4级 信号机软件故障',
        '5': '5级 信号机软硬件故障'
    }

    # 准备图表数据
    chart_data = {
        'region': {
            'labels': [r[0] for r in region_stats],
            'data': [r[1] for r in region_stats],
            'type': 'pie'
        },
        'junction': {
            'labels': [j[0] for j in junction_stats],
            'data': [j[1] for j in junction_stats],
            'type': 'bar'
        },
        'signal': {
            'labels': [s[0] for s in signal_stats],
            'data': [s[1] for s in signal_stats],
            'type': 'bar'
        },
        'level': {
            'labels': [level_mapping.get(l[0], '未知') for l in level_stats],
            'data': [l[1] for l in level_stats],
            'type': 'doughnut'
        },
        'monthly': {
            'labels': [m['label'] for m in monthly_data],
            'data': [m['count'] for m in monthly_data],
            'type': 'line'
        },
        'reporter': {
            'labels': [r[0] for r in reporter_stats],
            'data': [r[1] for r in reporter_stats],
            'type': 'horizontalBar'
        },
        'project': {
            'labels': [p[0] for p in project_stats],
            'data': [p[1] for p in project_stats],
            'type': 'bar'
        }
    }

    return render_template('statistics.html', chart_data=chart_data)




####看板路由
@app.route('/dashboard')
@login_required
def dashboard():
    # 获取当前年份
    current_year = datetime.now().year

    # 区域统计
    region_stats = db.session.query(
        FaultReport.region,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.region).all()

    # 故障等级统计
    level_stats = db.session.query(
        FaultReport.fault_level,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.fault_level).order_by(FaultReport.fault_level).all()


    # 路口故障TOP10
    junction_stats = db.session.query(
        FaultReport.junction,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.junction).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 信号机故障TOP10
    signal_stats = db.session.query(
        FaultReport.signal_id,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.signal_id).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 月度趋势（最近12个月）
    end_date = datetime.now()
    start_date = end_date - timedelta(days=365)
    monthly_stats = db.session.query(
        func.extract('year', FaultReport.fault_time).label('year'),
        func.extract('month', FaultReport.fault_time).label('month'),
        func.count(FaultReport.id).label('count')
    ).filter(FaultReport.fault_time >= start_date).group_by('year', 'month').order_by('year', 'month').all()

    # 提交人统计TOP10
    reporter_stats = db.session.query(
        FaultReport.reporter,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.reporter).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 项目统计TOP10
    project_stats = db.session.query(
        FaultReport.project,
        func.count(FaultReport.id).label('count')
    ).group_by(FaultReport.project).order_by(func.count(FaultReport.id).desc()).limit(10).all()

    # 准备模板数据
    data = {
        'current_year': current_year,
        'region_stats_labels': [r[0] for r in region_stats],
        'region_stats_data': [r[1] for r in region_stats],
        # 添加故障等级数据
        'level_stats': level_stats,  # 传递原始数据
        'level_stats_labels': [get_fault_level_display(level) for level, count in level_stats],
        'level_stats_data': [count for level, count in level_stats],
        'junction_stats_labels': [j[0] for j in junction_stats],
        'junction_stats_data': [j[1] for j in junction_stats],
        'signal_stats_labels': [s[0] for s in signal_stats],
        'signal_stats_data': [s[1] for s in signal_stats],
        'monthly_stats_labels': [f"{int(year)}年{int(month)}月" for year, month, _ in monthly_stats],
        'monthly_stats_data': [count for _, _, count in monthly_stats],
        'reporter_stats_labels': [r[0] for r in reporter_stats],
        'reporter_stats_data': [r[1] for r in reporter_stats],
        'project_stats_labels': [p[0] for p in project_stats],
        'project_stats_data': [p[1] for p in project_stats]
    }

    return render_template('dashboard.html', **data)

# 辅助函数：将故障等级代码转换为文字描述
@app.template_global()
def get_fault_level_display(level):
    levels = {
        '1': '1级 线路故障',
        '2': '2级 灯具故障',
        '3': '3级 信号机硬件故障',
        '4': '4级 信号机软件故障',
        '5': '5级 信号机软硬件故障'
    }
    return levels.get(level, '未知等级')
# 初始化数据库
initialize_database()

# 主程序入口
if __name__ == '__main__':
    # 启动开发服务器（生产环境应使用生产服务器）
    app.run(debug=False ,host='0.0.0.0',port=8000)
