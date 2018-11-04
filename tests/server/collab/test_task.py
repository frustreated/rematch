import pytest

from utils import create_model


@pytest.mark.parametrize('params', [{},
                                    {'source_start': 1000},
                                    {'source_end': 1000},
                                    {'target_file': 'files'},
                                    {'strategy': 'binning_strategy'}])
def test_empty_task(admin_user, params):
  task = create_model('tasks', admin_user, **params)
  task.save()

  from collab.tasks import match
  match(task.id)


def test_task(admin_user):
  task = create_model('tasks', admin_user, target_project=None)
  task.save()

  create_model('vectors', admin_user,
               file_version=task.source_file_version).save()
  create_model('vectors', admin_user,
               file_version=task.source_file_version).save()
  create_model('vectors', admin_user).save()
  create_model('vectors', admin_user).save()
  create_model('vectors', admin_user).save()

  from collab.tasks import match
  match(task.id)


def test_task_nonexistant_matcher(admin_user):
  task = create_model('tasks', admin_user, matchers='["nonexistant_matcher"]')
  task.save()

  from collab.tasks import match
  with pytest.raises(ValueError) as ex:
    match(task.id)
  assert 'Unfamiliar matchers were requested' in ex.value.args[0]
