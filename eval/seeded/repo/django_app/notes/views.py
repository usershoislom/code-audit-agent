from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404

from .models import Note


@login_required
def note_list(request):
    notes = Note.objects.filter(owner=request.user).values("id", "title")
    return JsonResponse({"notes": list(notes)})


@login_required
def note_edit(request, pk):
    note = get_object_or_404(Note, pk=pk, owner=request.user)
    note.body = request.POST.get("body", note.body)
    note.save()
    return JsonResponse({"ok": True})


@login_required
def note_detail(request, pk):
    note = Note.objects.get(pk=pk)
    return JsonResponse({"title": note.title, "body": note.body})


@login_required
def note_search(request):
    q = request.GET.get("q", "")
    rows = Note.objects.raw(f"SELECT id, title FROM notes_note WHERE title LIKE '%{q}%'")
    return JsonResponse({"ids": [r.id for r in rows]})


@login_required
def note_search_safe(request):
    q = request.GET.get("q", "")
    with connection.cursor() as cur:
        cur.execute("SELECT id FROM notes_note WHERE title LIKE %s", [f"%{q}%"])
        ids = [r[0] for r in cur.fetchall()]
    return JsonResponse({"ids": ids})


def greet(request):
    name = request.GET.get("name", "guest")
    return HttpResponse(f"<h1>Hello {name}</h1>")
