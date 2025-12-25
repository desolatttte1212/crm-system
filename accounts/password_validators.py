# accounts/password_validators.py
import re
from django.core.exceptions import ValidationError

def validate_strong_password(password):
    """
    Проверяет, что пароль:
    - минимум 8 символов
    - содержит хотя бы одну букву
    - содержит хотя бы одну цифру
    - содержит хотя бы один специальный символ
    """
    if len(password) < 8:
        raise ValidationError("Пароль должен содержать не менее 8 символов.")

    if not re.search(r'[a-zA-Z]', password):
        raise ValidationError("Пароль должен содержать хотя бы одну букву.")

    if not re.search(r'\d', password):
        raise ValidationError("Пароль должен содержать хотя бы одну цифру.")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError("Пароль должен содержать хотя бы один специальный символ (!@#$%^&* и т.д.).")