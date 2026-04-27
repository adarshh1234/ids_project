import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# -------------------------------
# LOAD DATASET (FIXED PATH)
# -------------------------------

columns = [
'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root',
'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
'dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
'label','difficulty'
]

df = pd.read_csv("../dataset/KDDTrain+.txt", names=columns)

# Remove extra column
df.drop(['difficulty'], axis=1, inplace=True)

# -------------------------------
# MAP LABELS
# -------------------------------

def map_attack(label):
    if label == 'normal':
        return 'Normal'
    elif label in ['neptune','smurf','back','teardrop','pod','land']:
        return 'DoS'
    elif label in ['ipsweep','nmap','portsweep','satan']:
        return 'Probe'
    elif label in ['guess_passwd','ftp_write','imap','phf','multihop','warezmaster','warezclient']:
        return 'R2L'
    else:
        return 'U2R'

df['label'] = df['label'].apply(map_attack)

# -------------------------------
# ENCODE
# -------------------------------

for col in ['protocol_type','service','flag']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])

# -------------------------------
# SPLIT
# -------------------------------

X = df.drop('label', axis=1)
y = df['label']

feature_cols = X.columns

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -------------------------------
# TRAIN
# -------------------------------

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)

# -------------------------------
# OUTPUT FOLDER
# -------------------------------

os.makedirs("chapters", exist_ok=True)

# -------------------------------
# FIG 4.1
# -------------------------------

report = classification_report(y_test, y_pred)

fig, ax = plt.subplots(figsize=(10, 4))
ax.text(0, 1, report, family='monospace', fontsize=10, va='top')
ax.axis('off')
plt.savefig('chapters/classification_report.png', bbox_inches='tight', dpi=150)
plt.close()

# -------------------------------
# FIG 4.2
# -------------------------------

importances = rf.feature_importances_
indices = np.argsort(importances)[-20:]

plt.figure(figsize=(10, 8))
plt.barh(range(len(indices)), importances[indices])
plt.yticks(range(len(indices)), [feature_cols[i] for i in indices])
plt.xlabel('Feature Importance Score')
plt.savefig('chapters/feature_importance.png', bbox_inches='tight', dpi=150)
plt.close()

# -------------------------------
# FIG 4.5
# -------------------------------

cm = confusion_matrix(y_test, y_pred)

disp = ConfusionMatrixDisplay(confusion_matrix=cm)
disp.plot()
plt.savefig('chapters/confusion_matrix.png', bbox_inches='tight', dpi=150)
plt.close()

print("✅ All images generated inside 'chapters/' folder")