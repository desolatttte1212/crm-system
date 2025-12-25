from django.db import models
from django.contrib.auth import get_user_model
from accounts.models import Request  # строковая ссылка

User = get_user_model()


class Task(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Низкий'),
        ('medium', 'Средний'),
        ('high', 'Высокий'),
        ('urgent', 'Срочно'),
    ]

    STATUS_CHOICES = [
        ('todo', 'К выполнению'),
        ('in_progress', 'В работе'),
        ('done', 'Выполнено'),
        ('cancelled', 'Отменено'),
    ]

    title = models.CharField("Название задачи", max_length=200)
    description = models.TextField("Описание", blank=True)

    assigned_to = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="assigned_tasks",
        verbose_name="Исполнитель"
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_tasks",
        verbose_name="Постановщик"
    )

    # 🔥 Строковая ссылка на Request из другого приложения
    request = models.ForeignKey(
        'accounts.Request',
        on_delete=models.CASCADE,
        related_name="tasks",
        verbose_name="Заявка / Проект",
        null=True,
        blank=True
    )

    priority = models.CharField("Приоритет", max_length=10, choices=PRIORITY_CHOICES, default='medium')
    status = models.CharField("Статус", max_length=20, choices=STATUS_CHOICES, default='todo')

    # ✅ Причина отмены (видна только CEO и Lead)
    cancellation_reason = models.TextField("Причина отмены", blank=True, null=True)

    due_date = models.DateField("Срок выполнения", null=True, blank=True)
    created_at = models.DateTimeField("Создана", auto_now_add=True)
    updated_at = models.DateTimeField("Обновлена", auto_now=True)

    def __str__(self):
        return f"{self.title} → {self.assigned_to.get_full_name() or self.assigned_to.username}"

    class Meta:
        verbose_name = "Задача"
        verbose_name_plural = "Задачи"
        ordering = ['-created_at']