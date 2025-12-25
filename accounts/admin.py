# accounts/admin.py
from django.contrib import admin
from .models import Profile, Request, Notification, Product, InventoryLog


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'company_name', 'full_name', 'phone', 'email', 'is_profile_complete')
    list_filter = ('is_profile_complete',)
    search_fields = ('user__username', 'company_name', 'full_name', 'phone')
    readonly_fields = ('user',)

    def get_readonly_fields(self, request, obj=None):
        if obj:  # При редактировании
            return self.readonly_fields
        return ()


@admin.register(Request)
class RequestAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'get_product_info', 'quantity', 'delivery_type', 'status', 'created_at']
    list_filter = ['status', 'delivery_type', 'created_at']
    search_fields = ['user__username', 'product_name', 'product__name']
    list_editable = ['status']
    readonly_fields = ['created_at']

    fieldsets = (
        ('Основная информация', {
            'fields': ('user', 'product', 'product_name', 'quantity', 'delivery_type', 'status')
        }),
        ('Стоимость и сроки', {
            'fields': ('cost_estimate', 'delivery_estimate')
        }),
        ('Комментарии', {
            'fields': ('manager_comment', 'cto_comment')
        }),
        ('Документы', {
            'fields': ('contract_file', 'signed_contract_file', 'invoice_file',
                       'client_signed_contract', 'client_signed_invoice',
                       'shipping_docs', 'client_signed_shipping_docs')
        }),
        ('Согласование с клиентом', {
            'fields': ('client_approved', 'client_approval_date',
                       'client_rejection_reason', 'client_response_received')
        }),
        ('Системная информация', {
            'fields': ('created_at', 'updated_at', 'assigned_manager')
        }),
    )

    def get_product_info(self, obj):
        """Отображает информацию о товаре в списке"""
        if obj.product:
            return f"{obj.product.name} (ID: {obj.product.id})"
        return obj.product_name or "Не указан"

    get_product_info.short_description = 'Товар'


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'message', 'is_read', 'created_at']
    list_filter = ['is_read', 'created_at']
    readonly_fields = ['created_at']


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['name', 'price', 'quantity', 'is_available', 'created_at']
    list_filter = ['is_available', 'created_at']
    search_fields = ['name', 'description']
    list_editable = ['price', 'quantity', 'is_available']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        ('Основная информация', {
            'fields': ('name', 'description', 'price', 'quantity', 'is_available')
        }),
        ('Системная информация', {
            'fields': ('created_at', 'updated_at')
        }),
    )


@admin.register(InventoryLog)
class InventoryLogAdmin(admin.ModelAdmin):
    list_display = ['product', 'movement_type', 'quantity', 'user', 'created_at']
    list_filter = ['movement_type', 'created_at']
    readonly_fields = ['created_at']
    search_fields = ['product__name', 'description']

    fieldsets = (
        ('Информация о движении', {
            'fields': ('product', 'movement_type', 'quantity', 'description')
        }),
        ('Системная информация', {
            'fields': ('user', 'created_at')
        }),
    )