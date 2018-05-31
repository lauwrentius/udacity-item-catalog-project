from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello AWS!"


if __name__ == '__main__':
    app.secret_key = '1GrSamWXZ8ikGhg43UIUbw5X'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
