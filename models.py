from flask_login import UserMixin
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # 2026-10-07：明文 → werkzeug pbkdf2:sha256 哈希（约 102 字符），列宽放宽到 255
    password = db.Column(db.String(255), nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='user')
    # 首登强制改密标记（存量账号统一置 1）
    must_change_password = db.Column(db.Boolean, nullable=False, default=True)
    # 禁用标记：被禁用的账号无法登录
    disabled = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f'<User {self.username}>'


class FaultReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    region = db.Column(db.String(50), nullable=False)  # 新增区域字段
    junction = db.Column(db.String(100), nullable=False)
    project = db.Column(db.String(100), nullable=False)
    signal_id = db.Column(db.String(50), nullable=False)
    signal_version = db.Column(db.String(50), nullable=False)  # 新增信号机程序版本字段
    fault_time = db.Column(db.DateTime, nullable=False)  # 新增故障发生时间字段
    fault_phenomenon = db.Column(db.Text, nullable=False)
    solution = db.Column(db.Text)
    fault_level = db.Column(db.String(20), nullable=False)  # 增加长度限制
    reporter = db.Column(db.String(100), nullable=False)
    report_time = db.Column(db.DateTime, default=datetime.now)
    # 字段添加索引
    region = db.Column(db.String(50), index=True)  # 添加索引
    junction = db.Column(db.String(100), index=True)  # 添加索引
    project = db.Column(db.String(100), index=True)  # 添加索引
    signal_id = db.Column(db.String(50), index=True)  # 添加索引
    fault_level = db.Column(db.String(10), index=True)  # 添加索引
    report_time = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加索引
    fault_time = db.Column(db.DateTime, index=True)  # 添加索引
    def __repr__(self):
        return f'<FaultReport {self.id} - {self.junction}>'
