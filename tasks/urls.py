from django.urls import path
from . import views

app_name = 'tasks'

urlpatterns = [
    path('', views.task_list, name='list'),
    path('<int:task_id>/priority/', views.update_task_priority, name='update_priority'),
    path('<int:task_id>/description/', views.update_task_description, name='update_description'),
    path('<int:task_id>/status/', views.update_task_status, name='update_status'),
    path('<int:task_id>/delete/', views.delete_task, name='delete_task'),
]