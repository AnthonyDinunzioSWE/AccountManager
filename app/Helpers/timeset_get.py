from datetime import datetime

def timeset_get():
    current_time = datetime.now()
    current_hour = current_time.hour
    
    if current_hour < 12:
        return "morning"
    elif 12 <= current_hour < 18:
        return "afternoon"
    else:
        return "evening"
