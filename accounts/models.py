# accounts/models.py
from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    """
    Профиль клиента с обязательными полями для создания заявок.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    # Для юрлица
    company_name = models.CharField(max_length=100, blank=True, verbose_name="Название компании")
    inn = models.CharField(max_length=12, blank=True, verbose_name="ИНН")

    # Для частного лица
    full_name = models.CharField(max_length=100, blank=True, verbose_name="ФИО")

    # Общие поля
    phone = models.CharField(max_length=20, verbose_name="Телефон")
    email = models.EmailField(verbose_name="Email")
    address = models.TextField(blank=True, verbose_name="Адрес")

    # Флаг завершения профиля
    is_profile_complete = models.BooleanField(default=False, verbose_name="Профиль заполнен")

    def __str__(self):
        return self.company_name or self.full_name or f"Профиль {self.user.username}"

    class Meta:
        verbose_name = "Профиль клиента"
        verbose_name_plural = "Профили клиентов"


class Product(models.Model):
    name = models.CharField(max_length=200, verbose_name="Название товара")
    description = models.TextField(blank=True, verbose_name="Описание")
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Цена (₽)")
    quantity = models.PositiveIntegerField(default=0, verbose_name="Количество на складе")
    is_available = models.BooleanField(default=True, verbose_name="В наличии")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Товар"
        verbose_name_plural = "Товары"
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class Request(models.Model):
    cost_estimate = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name="Расчётная стоимость"
    )
    delivery_estimate = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="Сроки поставки"
    )

    # Согласование с клиентом
    client_approved = models.BooleanField(null=True, blank=True, verbose_name="Клиент одобрил")
    client_approval_date = models.DateTimeField(null=True, blank=True, verbose_name="Дата согласования")

    contract_file = models.FileField(
        upload_to='contracts/',
        null=True,
        blank=True,
        verbose_name="Договор / Спецификация"
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Товар со склада"
    )
    signed_contract_file = models.FileField(
        upload_to='signed_contracts/',
        null=True,
        blank=True,
        verbose_name="Подписанный договор"
    )
    invoice_file = models.FileField(
        upload_to='invoices/',
        null=True,
        blank=True,
        verbose_name="Счёт"
    )
    shipping_docs = models.FileField(
        upload_to='shipping_docs/',
        null=True,
        blank=True,
        verbose_name="Отгрузочные документы"
    )
    client_signed_shipping_docs = models.FileField(
        upload_to='client_signed_shipping/',
        null=True,
        blank=True,
        verbose_name="Подписанные клиентом отгрузочные документы"
    )
    client_rejection_reason = models.TextField(
        blank=True,
        null=True,
        verbose_name="Причина отклонения клиентом"
    )

    # Признак: клиент ответил на расчёт стоимости
    client_response_received = models.BooleanField(default=False, verbose_name="Ответ от клиента получен")
    # Новые статусы
    STATUS_CHOICES = [
        ('sent', 'Отправлена'),
        ('processing', 'В обработке'),
        ('awaiting_tkp', 'Ожидание ТКП'),
        ('awaiting_approval', 'На согласовании'),
        ('awaiting_cost', 'Ожидание расчёта стоимости'),
        ('awaiting_client', 'На согласовании у клиента'),
        ('awaiting_documents', 'На оформлении документов'),
        ('documents_ready', 'Документы готовы'),
        ('awaiting_client_signature', 'На подписание у клиента'),
        ('signed_by_client', 'Подписано клиентом'),
        ('in_production', 'В производстве'),
        ('ready_for_delivery', 'Готова к отгрузке'),
        ('awaiting_shipping_docs', 'На оформлении отгрузки'),
        ('shipping_docs_ready', 'Отгрузочные документы готовы'),
        ('client_signed_shipping', 'Клиент подписал отгрузку'),
        ('awaiting_payment', 'Ожидание оплаты'),
        ('payment_confirmed', 'Оплата подтверждена'),
        ('completed', 'Выполнена'),
        ('cancelled', 'Отменена'),
    ]

    DELIVERY_CHOICES = [
        ('pickup', 'Самовывоз'),
        ('delivery', 'Доставка'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product_name = models.CharField(max_length=100, verbose_name="Товар")
    quantity = models.PositiveIntegerField(verbose_name="Количество")
    delivery_type = models.CharField(max_length=20, choices=DELIVERY_CHOICES, verbose_name="Тип доставки")
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='sent', verbose_name="Статус")
    manager_comment = models.TextField(
        blank=True, null=True,
        verbose_name="Комментарий менеджера",
        help_text="Видно клиенту"
    )
    cto_comment = models.TextField(
        blank=True, null=True,
        verbose_name="Комментарий КТО",
        help_text="Техническая оценка, видно только менеджеру и КТО"
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата создания")
    updated_at = models.DateTimeField(auto_now=True)
    assigned_manager = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        limit_choices_to={'groups__name__in': ['Managers', 'Lead Managers']},
        related_name='assigned_requests',
        verbose_name="Назначенный менеджер"
    )
    client_signed_contract = models.FileField(
        upload_to='client_signed_contracts/',
        null=True,
        blank=True,
        verbose_name="Подписанный клиентом договор"
    )
    client_signed_invoice = models.FileField(
        upload_to='client_signed_invoices/',
        null=True,
        blank=True,
        verbose_name="Подписанный клиентом счёт"
    )

    def __str__(self):
        return f"{self.product_name} — {self.get_status_display()}"

    class Meta:
        verbose_name = "Заявка"
        verbose_name_plural = "Заявки"
        ordering = ['-created_at']


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.CharField(max_length=255)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Для {self.user.username}: {self.message}"


class InventoryLog(models.Model):
    MOVEMENT_TYPES = (
        ('incoming', 'Приход'),
        ('outgoing', 'Расход'),
        ('adjustment', 'Корректировка'),
    )

    product = models.ForeignKey(Product, on_delete=models.CASCADE, verbose_name="Товар")
    movement_type = models.CharField(max_length=20, choices=MOVEMENT_TYPES, verbose_name="Тип движения")
    quantity = models.IntegerField(verbose_name="Количество")
    description = models.CharField(max_length=255, blank=True, verbose_name="Описание")
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, verbose_name="Кто внес")

    class Meta:
        verbose_name = "Запись в журнале склада"
        verbose_name_plural = "Журнал склада"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_movement_type_display()} {self.quantity} шт. — {self.product.name}"