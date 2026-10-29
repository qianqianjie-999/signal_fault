from app import app, db
with app.app_context():
    db.create_all()
    # 检查管理员用户是否存在
    if not User.query.filter_by(username='admin').first():
        # 创建初始管理员用户
        admin = User(username='admin', password='admin123', fullname='系统管理员', role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Database initialized and admin user created.")
