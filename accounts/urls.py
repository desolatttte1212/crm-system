# accounts/urls.py
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path('', RedirectView.as_view(url='home/')),
    path('register/', views.secure_register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('home/', views.home_view, name='home'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('my-requests/', views.my_requests_view, name='my_requests'),
    path('create-request/', views.create_request_view, name='create_request'),

    # Менеджеры
    path('manager/', views.manager_requests_view, name='manager_requests'),
    path('manager/update-status/<int:request_id>/', views.manager_update_request_status, name='update_request_status'),
    path('manager/comment/<int:request_id>/', views.add_comment_view, name='add_comment'),
    path('manager/clients/', views.manager_clients, name='manager_clients'),

    # Главный менеджер
    path('lead-manager/', views.lead_manager_dashboard, name='lead_manager_page'),
    path('lead-manager/assign/<int:request_id>/', views.assign_request_to_manager, name='assign_request_to_manager'),
    path('lead-manager/unassign/<int:request_id>/', views.unassign_request, name='unassign_request'),
    path('lead-manager/clients/', views.lead_manager_clients, name='lead_manager_clients'),

    path('lead/assign/<int:request_id>/', views.assign_request_to_manager, name='assign_request_to_manager'),

    # Уведомления
    path('mark-notifications-read/', views.mark_notifications_as_read, name='mark_notifications_as_read'),
    path('delete-notification/<int:notification_id>/', views.delete_notification, name='delete_notification'),

    # Админ
    path('admin-panel/', views.system_admin_panel, name='system_admin_panel'),
    path('admin-panel/set-role/<int:user_id>/', views.set_user_role, name='set_user_role'),

    # КТО
    path('cto/', views.cto_department_view, name='cto_department'),
    path('cto/approve/<int:request_id>/', views.cto_approve_for_cost, name='cto_approve_for_cost'),
    path('cto/reject/<int:request_id>/', views.cto_reject, name='cto_reject'),
    path('cto/update/<int:request_id>/', views.cto_update_request_status, name='cto_update_status'),
    path('manager/add-cto-comment/<int:request_id>/', views.cto_add_comment, name='add_cto_comment'),
    path('cto/add-comment/<int:request_id>/', views.cto_add_comment, name='cto_add_comment'),

    # Экономист
    path('economist/', views.economist_view, name='economist_dashboard'),
    path('economist/update/<int:request_id>/', views.economist_update_cost, name='economist_update_cost'),
    path('economist/cancel/<int:request_id>/', views.economist_cancel, name='economist_cancel'),

    # Ответ клиента на заявку
    path('request/approve/<int:request_id>/', views.client_approve, name='client_approve'),
    path('request/reject/<int:request_id>/', views.client_reject, name='client_reject'),

    # ген директор
    path('ceo/', views.ceo_dashboard, name='ceo_dashboard'),
    path('ceo/sign/<int:request_id>/', views.ceo_sign_contract, name='ceo_sign_contract'),

    # бухгалтерия
    path('accountant/', views.accountant_dashboard, name='accountant_dashboard'),
    path('accountant/invoice/<int:request_id>/', views.accountant_create_invoice, name='accountant_create_invoice'),

    path('request/sign-documents/<int:request_id>/', views.client_sign_documents, name='client_sign_documents'),

    path('manager/send-to-ceo-and-accountant/<int:request_id>/', views.send_to_ceo_and_accountant, name='send_to_ceo_and_accountant'),
    path('manager/send-documents-to-client/<int:request_id>/', views.send_documents_to_client, name='send_documents_to_client'),

    path('manager/send-to-production/<int:request_id>/', views.send_to_production, name='send_to_production'),

    # accounts/urls.py
    path('production/', views.production_dashboard, name='production_dashboard'),
    path('production/request/<int:request_id>/status/', views.production_update_request_status,
         name='production_update_request_status'),

    path('accountant/add-shipping/<int:request_id>/', views.accountant_add_shipping_docs, name='accountant_add_shipping_docs'),

    path('manager/send-shipping-to-client/<int:request_id>/', views.send_shipping_docs_to_client, name='send_shipping_docs_to_client'),

    path('request/sign-shipping/<int:request_id>/', views.client_sign_shipping_docs, name='client_sign_shipping_docs'),

    path('manager/mark-awaiting-payment/<int:request_id>/', views.mark_as_awaiting_payment, name='mark_as_awaiting_payment'),

    path('accountant/confirm-payment/<int:request_id>/', views.confirm_payment, name='confirm_payment'),

    path('manager/archive/', views.manager_archive, name='manager_archive'),

    path('profile/complete/', views.complete_profile, name='complete_profile'),

    path('client-response/<int:request_id>/', views.client_response, name='client_response'),

    path('manager/export-excel/', views.export_requests_excel, name='export_requests_excel'),

    path('warehouse/', views.warehouse_view, name='warehouse'),

    path('warehouse/manager/', views.warehouse_manager_view, name='warehouse_manager'),

    path('warehouse/add/', views.add_product, name='add_product'),

    path('warehouse/edit/<int:product_id>/', views.edit_product, name='edit_product'),

    path('warehouse/delete/<int:product_id>/', views.delete_product, name='delete_product'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
