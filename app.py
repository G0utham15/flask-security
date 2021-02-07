from flask import Flask, redirect, url_for, render_template, flash, request
from flask_security.forms import PasswordField
from flask_security import Security, login_required, \
     SQLAlchemySessionUserDatastore, roles_required, current_user, utils, UserMixin, RoleMixin, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_mail import Mail
from forms import registerForm
from flask_admin import Admin
from flask_admin.contrib import sqla
# Create app
app = Flask(__name__)
app.config.from_pyfile('config.cfg')
#app.config.from_pyfile('mail_config.cfg')
#app.config['SECURITY_EMAIL_SENDER']='admntest@yahoo.com'
# Setup Flask-Security

db=SQLAlchemy(app)


roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(db.Integer)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary='roles_users',
                         backref=db.backref('users', lazy='dynamic'))

user_datastore = SQLAlchemySessionUserDatastore(db.session,
                                                User, Role)
security = Security(app, user_datastore, register_form=registerForm)
#mail=Mail(app)
# Create a user to test with

class UserAdmin(sqla.ModelView):

    # Don't display the password on the list of Users
    column_exclude_list = ('password',)

    # Don't include the standard password field when creating or editing a User (but see below)
    form_excluded_columns = ('password',)

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Users unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

    # On the form for creating or editing a User, don't display a field corresponding to the model's password field.
    # There are two reasons for this. First, we want to encrypt the password before storing in the database. Second,
    # we want to use a password field (with the input masked) rather than a regular text field.
    def scaffold_form(self):

        # Start with the standard form as provided by Flask-Admin. We've already told Flask-Admin to exclude the
        # password field from this form.
        form_class = super(UserAdmin, self).scaffold_form()

        # Add a password field, naming it "password2" and labeling it "New Password".
        form_class.password2 = PasswordField('New Password')
        return form_class

    # This callback executes when the user saves changes to a newly-created or edited User -- before the changes are
    # committed to the database.
    def on_model_change(self, form, model, is_created):

        # If the password field isn't blank...
        if len(model.password2):

            # ... then encrypt the new password prior to storing it in the database. If the password field is blank,
            # the existing password in the database will be retained.
            model.password = utils.encrypt_password(model.password2)


# Customized Role model for SQL-Admin
class RoleAdmin(sqla.ModelView):

    # Prevent administration of Roles unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

# Initialize Flask-Admin
admin = Admin(app)

# Add Flask-Admin views for Users and Roles
admin.add_view(UserAdmin(User, db.session))
admin.add_view(RoleAdmin(Role, db.session))

@app.before_first_request
def create_user():
    try:
        admin_user=user_datastore.create_user(email='admin@test.com', username='admin15', password='admintest', last_login_at=datetime.now(), \
            current_login_at=datetime.now(), last_login_ip=request.environ.get('HTTP_X_REAL_IP', request.remote_addr), current_login_ip=request.environ.get('HTTP_X_REAL_IP', request.remote_addr), login_count=0, confirmed_at=datetime.now() )
        admin=user_datastore.find_or_create_role('admin')
        moderater=user_datastore.find_or_create_role('moderater')
        user=user_datastore.find_or_create_role('user')
        user_datastore.add_role_to_user(admin_user, admin)
        db.session.commit()
    except:
        pass
    

# Views
@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out Successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)