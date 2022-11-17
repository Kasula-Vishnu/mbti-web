from csv import writer
from sklearn.feature_extraction.text import TfidfVectorizer
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pickle
import re
import nltk
import pandas as pd
from numpy import vectorize
nltk.download('punkt')
nltk.download('wordnet')


'''model_XGB = pickle.load(open('model_XGB.pkl', 'rb'))'''
model_logreg = pickle.load(open('model_logreg.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


db.create_all()


class RegisterForm(FlaskForm):
    text_field_classes = "shadow appearance-none border rounded-full w-full py-4 px-7 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username", "class": text_field_classes})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password", "class": text_field_classes})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    text_field_classes = "shadow appearance-none border rounded-full w-full py-4 px-7 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"

    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username", "class": text_field_classes})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password", "class": text_field_classes})

    submit = SubmitField('Login')


def input_preprocesing(text):
    filter = []
    review = re.sub(
        'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' ', text)
    review = re.sub('[^a-zA-Z]', ' ', review)
    review = review.lower()
    stop_words = set(stopwords.words("english"))
    word_tokens = word_tokenize(review)
    filtered_text = [word for word in word_tokens if word not in stop_words]
    return filtered_text


@app.route('/')
def man():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/predict', methods=['POST'])
def home():
    print(request)
    data_1 = request.form['answer_0']
    data_2 = request.form['answer_1']
    data_3 = request.form['answer_2']
    data_4 = request.form['answer_3']
    data = " ".join([data_1, data_2, data_3, data_4])
    preprocessed_data = input_preprocesing(data)
    vectorized_data = vectorizer.transform(preprocessed_data)
    prediction = model_logreg.predict(vectorized_data)[0]
    predictions = {
        0: 'ENFJ',
        1: 'ENFP',
        2: 'ENTJ',
        3: 'ENTP',
        4: 'ESFJ',
        5: 'ESFP',
        6: 'ESTJ',
        7: 'ESTP',
        8: 'INFJ',
        9: 'INFP',
        10: 'INTJ',
        11: 'INTP',
        12: 'ISFJ',
        13: 'ISFP',
        14: 'ISTJ',
        15: 'ISTP'
    }
    personality = predictions[prediction]

    new_data = [personality, data]

    with open('mbti_1.csv', 'a') as f_object:
        writer_object = writer(f_object)
        writer_object.writerow(new_data)
        f_object.close()

    return render_template('result.html', personality=personality)


if __name__ == '__main__':
    app.run(debug=True)
