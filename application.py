from flask import Flask

application = Flask(__name__)


@app.route("/")
def hello():
    return "Hello AWS!"


if __name__ == '__main__':
    application.secret_key = '1GrSamWXZ8ikGhg43UIUbw5X'
    application.debug = True
    application.run(host='0.0.0.0', port=5000)
