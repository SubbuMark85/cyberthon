from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Serve the frontend (HTML)
@app.route("/")
def home():
    return render_template("index.html")

# Example API endpoint
@app.route("/api/data", methods=["GET"])
def get_data():
    data = {"message": "Hello from Flask!"}
    return jsonify(data)

# Example POST request handler
@app.route("/api/submit", methods=["POST",'GET'])
def submit_data():
    user_input = request.json.get("input")
    return jsonify({"response": f"You said: {user_input}"})

if __name__ == "__main__":
    app.run(debug=True)