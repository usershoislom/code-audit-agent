from django.urls import path

from . import views

urlpatterns = [
    path("notes/", views.note_list),
    path("notes/<int:pk>/", views.note_detail),
    path("notes/<int:pk>/edit/", views.note_edit),
    path("notes/search/", views.note_search),
    path("notes/search2/", views.note_search_safe),
    path("hello/", views.greet),
]
