# tasks/templatetags/task_extras.py
from django import template

register = template.Library()

@register.filter
def is_created_by_ceo(task):
    """
    Проверяет, создана ли задача CEO
    """
    return task.created_by.groups.filter(name='CEO').exists()

@register.filter
def get_priority_color(priority):
    """
    Возвращает цвет приоритета
    """
    color_map = {
        'urgent': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#28a745',
    }
    return color_map.get(priority, '#6c757d')