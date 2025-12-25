from django import forms
from django.contrib.auth.models import User
from .models import Task

# Определим иерархию ролей (от низшей к высшей)
ROLE_HIERARCHY = [
    'Warehouse Manager',    # 0
    'Production',           # 1
    'CTO Department',       # 2
    'Economist',            # 3
    'Accountant',           # 4
    'Managers',             # 5
    'Lead Managers',        # 6
    'CEO',                  # 7
    'System Admin',         # 8
]

class TaskForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        # Получаем пользователя, который создает задачу (для ограничения списка)
        self.current_user = kwargs.pop('current_user', None)
        super().__init__(*args, **kwargs)

        # Фильтруем пользователей: только те, у кого есть роль из ROLE_HIERARCHY
        self.fields['assigned_to'].queryset = User.objects.filter(
            groups__name__in=ROLE_HIERARCHY
        ).distinct().order_by('username')

    class Meta:
        model = Task
        fields = ['title', 'description', 'assigned_to', 'priority', 'due_date']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Название задачи'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Описание задачи'}),
            'assigned_to': forms.Select(attrs={'class': 'form-control'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
            'due_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
        }