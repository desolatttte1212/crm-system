from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import Group, User
from django.utils import timezone
from .models import Task
from .forms import TaskForm

# Определим иерархию ролей (от низшей к высшей)
ROLE_HIERARCHY = [
    'Warehouse Manager',  # 0
    'Production',  # 1
    'CTO Department',  # 2
    'Economist',  # 3
    'Accountant',  # 4
    'Managers',  # 5
    'Lead Managers',  # 6
    'CEO',  # 7
    'System Admin',  # 8
]


def get_role_level(group_name):
    """Возвращает уровень роли (чем больше — тем выше в иерархии)"""
    try:
        return ROLE_HIERARCHY.index(group_name)
    except ValueError:
        return -1  # неизвестная роль


@login_required
def task_list(request):
    # 🔒 Запретить доступ, если у пользователя роль "Без роли"
    if request.user.groups.filter(name='Без роли').exists():
        messages.error(request, "У вас нет доступа к задачам.")
        return redirect('home')

    # ✅ Только лид-менеджеры и CEO видят все задачи
    user_group = request.user.groups.first()

    if user_group and user_group.name in ['Lead Managers', 'CEO']:
        all_tasks = Task.objects.select_related('assigned_to', 'request', 'created_by').order_by('-created_at')
    else:
        # ✅ Обычные сотрудники видят только свои задачи
        all_tasks = Task.objects.filter(assigned_to=request.user).select_related('request', 'created_by').order_by(
            '-created_at')

    # Форма создания задачи (только для лид-менеджеров и CEO)
    form = None
    available_users = []

    # ✅ Только лид-менеджеры и CEO могут создавать задачи
    if user_group and user_group.name in ['Lead Managers', 'CEO']:
        user_role_level = get_role_level(user_group.name)

        # Для Lead Managers: только роли ниже
        if user_group.name == 'Lead Managers':
            allowed_roles = ROLE_HIERARCHY[:user_role_level]  # только ниже
        else:  # CEO
            allowed_roles = ROLE_HIERARCHY  # все роли

        # Получаем пользователей с разрешёнными ролями
        available_users = User.objects.filter(
            groups__name__in=allowed_roles
        ).distinct().order_by('username')

        # ✅ Передаём текущего пользователя в форму
        form = TaskForm(current_user=request.user)

    # Обработка POST-запроса (создание задачи)
    if request.method == 'POST':
        # 🔒 Проверяем, может ли пользователь создавать задачи
        if not (user_group and user_group.name in ['Lead Managers', 'CEO']):
            messages.error(request, "У вас нет прав на создание задач.")
            return redirect('tasks:list')

        # ✅ Передаём пользователя в форму при POST-запросе
        form = TaskForm(request.POST, current_user=request.user)
        if form.is_valid():
            task = form.save(commit=False)
            assigned_user = task.assigned_to
            assigned_group = assigned_user.groups.first()

            # Проверяем права на назначение
            if user_group and assigned_group:
                user_role_level = get_role_level(user_group.name)
                assigned_role_level = get_role_level(assigned_group.name)

                # Лид-менеджер не может назначать задачи выше своего уровня
                if user_group.name == 'Lead Managers' and assigned_role_level >= user_role_level:
                    messages.error(request,
                                   "Вы не можете назначать задачи пользователям с такой же или более высокой ролью.")
                else:
                    task.created_by = request.user
                    task.save()
                    messages.success(request, f"Задача '{task.title}' создана для {assigned_user.username}")
                    return redirect('tasks:list')
            else:
                messages.error(request, "Не удалось определить роли для проверки доступа.")

    # ✅ Подготовим список задач с флагом "создана CEO"
    tasks_with_data = []
    for task in all_tasks:
        is_created_by_ceo = task.created_by.groups.filter(name='CEO').exists()
        tasks_with_data.append({
            'task': task,
            'is_created_by_ceo': is_created_by_ceo
        })

    return render(request, 'tasks/task_list.html', {
        'all_tasks': tasks_with_data,
        'form': form,
        'available_users': available_users,
        'user_group': user_group.name if user_group else None,
        'today': timezone.now().date(),  # ✅ Передаём сегодняшнюю дату
    })


@login_required
def update_task_priority(request, task_id):
    """
    Обновление приоритета задачи
    """
    task = get_object_or_404(Task, id=task_id)
    user_group = request.user.groups.first()

    # 🔒 Проверяем, может ли пользователь изменять приоритет
    if not user_group or user_group.name not in ['Lead Managers', 'CEO']:
        messages.error(request, "У вас нет прав на изменение приоритета задач.")
        return redirect('tasks:list')

    # 🔒 Лид не может менять приоритет задач, созданных CEO
    if user_group.name == 'Lead Managers' and task.created_by.groups.filter(name='CEO').exists():
        messages.error(request, "Вы не можете изменить приоритет задачи, созданной генеральным директором.")
        return redirect('tasks:list')

    if request.method == 'POST':
        new_priority = request.POST.get('priority')
        if new_priority in ['low', 'medium', 'high', 'urgent']:
            task.priority = new_priority
            task.save()
            messages.success(request, f"Приоритет задачи '{task.title}' изменён на {task.get_priority_display()}")
        else:
            messages.error(request, "Неверное значение приоритета.")

    return redirect('tasks:list')


@login_required
def update_task_description(request, task_id):
    """
    Обновление описания задачи
    """
    task = get_object_or_404(Task, id=task_id)
    user_group = request.user.groups.first()

    # 🔒 Проверяем, может ли пользователь изменять описание
    if not user_group or user_group.name not in ['Lead Managers', 'CEO']:
        messages.error(request, "У вас нет прав на изменение описания задачи.")
        return redirect('tasks:list')

    if request.method == 'POST':
        new_description = request.POST.get('description')
        task.description = new_description
        task.save()
        messages.success(request, f"Описание задачи '{task.title}' изменено.")

    return redirect('tasks:list')


@login_required
def update_task_status(request, task_id):
    """
    Обновление статуса задачи
    """
    task = get_object_or_404(Task, id=task_id)
    user_group = request.user.groups.first()

    # ✅ Проверяем, может ли пользователь изменять статус
    # - Исполнитель задачи
    # - Создатель задачи
    # - Lead
    # - CEO
    can_change_status = (
            task.assigned_to == request.user or
            task.created_by == request.user or
            user_group and user_group.name in ['Lead Managers', 'CEO']
    )

    if not can_change_status:
        messages.error(request, "У вас нет прав на изменение статуса задачи.")
        return redirect('tasks:list')

    if request.method == 'POST':
        new_status = request.POST.get('status')
        cancellation_reason = request.POST.get('cancellation_reason', '').strip()

        if new_status not in ['todo', 'in_progress', 'done', 'cancelled']:
            messages.error(request, "Неверное значение статуса.")
            return redirect('tasks:list')

        if new_status == 'cancelled':
            if not cancellation_reason:
                messages.error(request, "При отмене задачи необходимо указать причину.")
                return redirect('tasks:list')
            task.cancellation_reason = cancellation_reason
        else:
            # Если задачу снова возвращают из отмены — очищаем причину
            task.cancellation_reason = None

        task.status = new_status
        task.save()
        messages.success(request, f"Статус задачи '{task.title}' изменён на {task.get_status_display()}")

    return redirect('tasks:list')


@login_required
def delete_task(request, task_id):
    """
    Удаление задачи
    """
    task = get_object_or_404(Task, id=task_id)
    user_group = request.user.groups.first()

    # 🔒 Проверяем, может ли пользователь удалить задачу
    if not user_group or user_group.name not in ['Lead Managers', 'CEO']:
        messages.error(request, "У вас нет прав на удаление задач.")
        return redirect('tasks:list')

    # 🔒 Лид не может удалить задачу, созданную CEO
    if user_group.name == 'Lead Managers' and task.created_by.groups.filter(name='CEO').exists():
        messages.error(request, "Вы не можете удалить задачу, созданную генеральным директором.")
        return redirect('tasks:list')

    # ✅ Проверяем, что задача отменена
    if task.status != 'cancelled':
        messages.error(request, "Можно удалить только отмененные задачи.")
        return redirect('tasks:list')

    task.delete()
    messages.success(request, f"Задача '{task.title}' удалена.")

    return redirect('tasks:list')