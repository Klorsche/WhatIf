
from django.urls import path
from . import views

urlpatterns = [
    path('data/', views.get_data, name='get_data'),
    path('submetrics/', views.get_submetrics, name='get_submetrics'),
    path('context-questions/', views.get_context_questions, name='get_context_questions'),
    path('calculate/', views.calculate_risk, name='calculate_risk'),
]
