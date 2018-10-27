import functools

from rest_framework import (viewsets, permissions, mixins, decorators, status,
                            response)

from django.db import models

import django_cte

from collab.models import (Project, File, FileVersion, Task, Instance, Vector,
                           Match, Annotation, Dependency)
from collab.serializers import (ProjectSerializer, FileSerializer,
                                FileVersionSerializer, TaskSerializer,
                                TaskEditSerializer, InstanceVectorSerializer,
                                VectorSerializer, MatchSerializer,
                                SlimInstanceSerializer, AnnotationSerializer,
                                MatcherSerializer, StrategySerializer,
                                DependencySerializer)
from collab.permissions import IsOwnerOrReadOnly
from collab import tasks
from collab.matchers import matchers_list
from collab.strategies import strategies_list


class ViewSetOwnerMixin(object):
  permission_classes = (permissions.IsAuthenticated, IsOwnerOrReadOnly)

  def perform_create(self, serializer):
    serializer.save(owner=self.request.user)


class ViewSetManyAllowedMixin(object):
  def get_serializer(self, *args, **kwargs):
    if "data" in kwargs:
      data = kwargs["data"]

      if isinstance(data, list):
        kwargs["many"] = True

    return super(ViewSetManyAllowedMixin, self).get_serializer(*args, **kwargs)


def paginatable(serializer):
  def decorator(f):
    @functools.wraps(f)
    def wraps(self, *args, **kwargs):
      queryset = f(self, *args, **kwargs)
      page = self.paginate_queryset(queryset)
      if page is not None:
        serialized = serializer(page, many=True)
        return self.get_paginated_response(serialized.data)
      else:
        serialized = serializer(queryset, many=True)
        return response.Response(serialized.data)
    return wraps
  return decorator


class ProjectViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = Project.objects.all()
  serializer_class = ProjectSerializer
  filterset_fields = ('created', 'owner', 'name', 'description', 'private')


class FileViewSet(ViewSetOwnerMixin, viewsets.ModelViewSet):
  queryset = File.objects.all()
  serializer_class = FileSerializer
  filterset_fields = ('created', 'owner', 'project', 'name', 'description',
                      'md5hash')

  @decorators.action(detail=True, methods=['GET', 'POST'],
                     url_path="file_version/(?P<md5hash>[0-9A-Fa-f]+)")
  def file_version(self, request, pk, md5hash):
    del pk
    file_obj = self.get_object()

    if request.method == 'POST':
      file_version, created = \
        FileVersion.objects.get_or_create(md5hash=md5hash, file=file_obj)
    else:
      file_version = FileVersion.objects.get(md5hash=md5hash, file=file_obj)
      created = False

    serializer = FileVersionSerializer(file_version)

    resp_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    response_data = serializer.data
    response_data['newly_created'] = created
    return response.Response(response_data, status=resp_status)


class FileVersionViewSet(viewsets.ModelViewSet):
  queryset = FileVersion.objects.all()
  serializer_class = FileVersionSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('id', 'file', 'md5hash')


class TaskViewSet(mixins.CreateModelMixin, mixins.RetrieveModelMixin,
                  mixins.DestroyModelMixin, mixins.ListModelMixin,
                  viewsets.GenericViewSet):
  queryset = Task.objects.all()
  permission_classes = (permissions.IsAuthenticated, IsOwnerOrReadOnly)
  filterset_fields = ('task_id', 'created', 'finished', 'owner', 'status')

  def perform_create(self, serializer):
    task = serializer.save(owner=self.request.user)
    tasks.match.delay(task_id=task.id)

  def get_serializer_class(self):
    serializer_class = TaskSerializer
    if self.request.method in ('PATCH', 'PUT'):
      serializer_class = TaskEditSerializer
    return serializer_class

  @decorators.action(detail=True, url_path="locals")
  @paginatable(SlimInstanceSerializer)
  def locals(self, request, pk):
    del request
    del pk

    task = self.get_object()

    # include local matches (created for specified file_version and are a
    # 'from_instance' match). for those, include the match objects themselves
    return Instance.objects.filter(from_matches__task=task).distinct()

  @decorators.action(detail=True, url_path="remotes")
  @paginatable(SlimInstanceSerializer)
  def remotes(self, request, pk):
    del request
    del pk

    task = self.get_object()

    # include remote matches (are a 'to_instance' match), those are referenced
    # by match records of local instances
    return Instance.objects.filter(to_matches__task=task).distinct()

  @decorators.action(detail=True, url_path="matches")
  @paginatable(MatchSerializer)
  def matches(self, request, pk):
    del request
    del pk

    task = self.get_object()

    return Match.objects.filter(task=task)


class MatchViewSet(viewsets.ReadOnlyModelViewSet):
  queryset = Match.objects.all()
  serializer_class = MatchSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('task', 'type', 'score')

  @staticmethod
  @decorators.action(detail=False)
  def matchers(request):
    del request
    if any((m.is_abstract() for m in matchers_list)):
      raise Exception("Abstract matcher in list")
    serializer = MatcherSerializer(matchers_list, many=True)
    return response.Response(serializer.data)

  @staticmethod
  @decorators.action(detail=False)
  def strategies(request):
    del request
    if any((s.is_abstract() for s in strategies_list)):
      raise Exception("Abstract strategy in list")
    serializer = StrategySerializer(strategies_list, many=True)
    return response.Response(serializer.data)


class InstanceViewSet(ViewSetManyAllowedMixin, ViewSetOwnerMixin,
                      viewsets.ModelViewSet):
  queryset = Instance.objects.all()
  serializer_class = InstanceVectorSerializer
  filterset_fields = ('owner', 'file_version', 'type')


class VectorViewSet(ViewSetManyAllowedMixin, viewsets.ModelViewSet):
  queryset = Vector.objects.all()
  serializer_class = VectorSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('instance', 'file_version', 'type', 'type_version')

  @staticmethod
  def perform_create(serializer):
    file_version = serializer.validated_data['instance'].file_version
    serializer.save(file_version=file_version)


class AnnotationViewSet(viewsets.ModelViewSet):
  queryset = Annotation.objects.all()
  serializer_class = AnnotationSerializer
  permission_classes = (permissions.IsAuthenticated,)
  filterset_fields = ('instance', 'type', 'data')

  @decorators.action(detail=False)
  @paginatable(AnnotationSerializer)
  def full_hierarchy(self, request):
    del self

    annotation_ids = request.query_params.getlist('ids')

    # TODO: perhaps only provide needed IDs here and fetch them using a
    # second query?
    def make_cte_subquery(cte):
      value0 = models.expressions.Value(0, output_field=models.IntegerField())
      value1 = models.expressions.Value(1, output_field=models.IntegerField())
      return (Annotation.objects.filter(id__in=annotation_ids)
              # .values("uuid", "instance", "type", "data",
              .values("id", "uuid", depth=value0)
              .union(cte.join(Annotation, dependents=cte.col.uuid)
                        .values("id", "uuid", depth=cte.col.depth + value1),
                     all=True))

    cte = django_cte.With.recursive(make_cte_subquery)

    annotations = (cte.join(Annotation, id=cte.col.id)
                      .with_cte(cte)
                      .annotate(depth=cte.col.depth)
                      .order_by("-depth"))

    return annotations


class DependencyViewSet(viewsets.ModelViewSet):
  queryset = Dependency.objects.all()
  serializer_class = DependencySerializer
  permission_classes = (permissions.IsAuthenticated,)
