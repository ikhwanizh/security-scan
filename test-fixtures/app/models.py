import pickle

import joblib
import torch


def load(model_path, data):
    with open(model_path, "rb") as f:
        topic_model = pickle.load(f)
    obj = pickle.loads(data)
    clf = joblib.load(model_path)
    w = torch.load(model_path)
    w2 = torch.load(model_path, weights_only=True)
    raw = pickle.dumps(obj)
    return topic_model, clf, w, w2, raw
