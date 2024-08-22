from flask import Flask, request, jsonify
from models.user import User, Meal
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt
from database import db
import os
from datetime import datetime




app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(app.instance_path, "database.db")}'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/user', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message":f"User {username} registered successfully"})
    

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), user.password):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({'message':'Authentication successfull'})
        
    return jsonify({'message':'Invalid credentials'}), 400

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message':'Logged out successfully'})

@app.route('/meals', methods=['POST'])
@login_required
def add_user_meal():
    data = request.json

    try:
        date = datetime.strptime(data['date'], '%d-%m-%Y').date()
        time = datetime.strptime(data['time'], '%H:%M:%S').time()
    except ValueError as e:
            return jsonify({'message': f'Invalid date or time format: {e}'}), 400

    new_meal = Meal(
        name = data['name'],
        calories = data['calories'],
        date = date,
        time = time,
        within_diet_plan= data.get('within_diet_plan', True),
        description = data.get('description', ""),
        user=current_user
    )
    db.session.add(new_meal)
    db.session.commit()
    return jsonify({'message':'Meal added to your diet'})

@app.route('/meals', methods=['GET'])
@login_required
def get_user_meals():
    meals = [{'id': meal.id, 'name': meal.name, 'calories': meal.calories, 'date': meal.date.strftime('%d-%m-%Y'), 'time': meal.time.strftime('%H:%M:%S'), 'withint_diet_plan': meal.within_diet_plan, 'description': meal.description} for meal in current_user.meals]
    return jsonify(meals)

@app.route('/meals/<int:meal_id>', methods=['PUT'])
@login_required
def edit_user_meal(meal_id):
    meal = Meal.query.filter_by(id=meal_id).first()

    if meal.user_id != current_user.id:
        return jsonify({"message": "You are not authorized to access or modify this meal"}), 404
    
    data = request.json
    meal.name = data.get('name')
    meal.calories = data.get('calories')
    meal.within_diet_plan = data.get('within_diet_plan')
    meal.description = data.get('meal.description')

    db.session.commit()
    return jsonify({'message': 'Meal updated'})


@app.route('/meals/<int:meal_id>', methods=['GET'])
@login_required
def get_single_meal(meal_id):
    meal = Meal.query.filter_by(id=meal_id).first()

    if not meal:
        return jsonify({'message': 'Meal not found'}), 404

    if meal.user_id != current_user.id:
        return jsonify({'message': 'You are not authorized to see this meal'}), 404
    
    return jsonify({'id': meal.id, 'name': meal.name, 'calories': meal.calories, 'date': meal.date.strftime('%d-%m-%Y'), 'time': meal.time.strftime('%H:%M:%S'), 'description': meal.description, 'within_diet_plan': meal.within_diet_plan})

@app.route('/meals/<int:meal_id>', methods=['DELETE'])
@login_required
def delete_meal(meal_id):
    meal = Meal.query.filter_by(id=meal_id).first()

    if not meal:
        return jsonify({'message':'Meal not found'})

    if meal.user_id != current_user.id:
        return jsonify({'message':'You are not authorized to delete this meal'})
    
    db.session.delete(meal)
    db.session.commit()
    return jsonify({'message': f'Meal {meal_id} successfully deleted'})

if __name__ == '__main__':
    app.run(debug=True)