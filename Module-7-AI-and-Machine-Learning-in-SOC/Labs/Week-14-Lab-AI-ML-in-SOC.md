_# Week 14 Lab: AI and Machine Learning in the SOC

## Learning Outcomes

By the end of this lab, you will be able to:

- Understand the role of AI and machine learning in a modern SOC.
- Use a machine learning model to detect malicious activity.
- Evaluate the performance of a machine learning model.
- Understand the challenges and limitations of using AI/ML in cybersecurity.

## 1. Objective

In this lab, you will explore the use of AI and machine learning in a Security Operations Center. You will use a pre-trained machine learning model to detect malicious network traffic and evaluate its performance.

## 2. Prerequisites

- Basic understanding of machine learning concepts (supervised vs. unsupervised learning, classification, etc.).
- A Python environment with the following libraries installed: `pandas`, `scikit-learn`, `numpy`.

## 3. Lab Steps

### Step 1: Download the Dataset

For this lab, we will use a pre-processed version of the CIC-IDS2017 dataset. This dataset has been cleaned and formatted for use with machine learning models.

- Download the dataset: [cic-ids2017-preprocessed.csv](./resources/cic-ids2017-preprocessed.csv)

### Step 2: Train a Machine Learning Model

We will use a simple machine learning model, a Decision Tree Classifier, to detect malicious traffic. The following Python script will train the model and save it to a file:

```python
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load the dataset
data = pd.read_csv("cic-ids2017-preprocessed.csv")

# Split the dataset into features (X) and labels (y)
X = data.drop("Label", axis=1)
y = data["Label"]

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
model = DecisionTreeClassifier()
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")

# Save the model
joblib.dump(model, "ids_model.pkl")
```

### Step 3: Use the Model to Make Predictions

Now that we have a trained model, we can use it to make predictions on new data. The following Python script will load the model and use it to predict whether a new network connection is malicious or benign:

```python
import joblib
import numpy as np

# Load the model
model = joblib.load("ids_model.pkl")

# Create a new network connection to classify
new_connection = np.array([[...]])  # Replace with actual data

# Make a prediction
prediction = model.predict(new_connection)

if prediction[0] == 1:
    print("Malicious connection detected!")
else:
    print("Benign connection.")
```

## 4. Deliverables

- The accuracy of your trained model.
- A screenshot of your script making a prediction on a new network connection.
- A brief discussion of the challenges and limitations of using AI/ML in cybersecurity.
_
