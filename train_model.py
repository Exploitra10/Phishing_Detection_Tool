import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# -----------------------------
# CREATE DATASET IN CODE
# -----------------------------
data = pd.DataFrame({
    "length": [22, 25, 26, 27, 34, 45, 28, 18, 24, 30],
    "has_at": [0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
    "has_https": [1, 1, 1, 1, 0, 1, 0, 1, 0, 1],
    "subdomains": [1, 1, 1, 1, 2, 0, 2, 1, 0, 1],
    "label": [0, 0, 0, 0, 1, 1, 1, 0, 1, 0]
})


# -Exploita_Project ------
#---mohdsahir10-----------
# TRAIN MODEL
# -----------------------------
X = data.drop("label", axis=1)
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

joblib.dump(model, "phishing_model.pkl")
print("\nModel saved as phishing_model.pkl")

