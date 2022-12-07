from flask import Flask

app = Flask(__name__)

def foo(a):
    print(a)

@app.route("/")
def hello_world():
    foo("blah")
    return "<p>Hello, World!</p>"

app.run()