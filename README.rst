Python client for Oncall API
==========================

Install
------

.. code-block:: bash

  pip install oncallclient


Usage
-----

.. code-block:: python

    from oncallclient import OncallClient

    client = OncallClient(
        app='SERVICE_FOO',
        key='oncall_API_KEY',
        api_host='http://localhost:5000'
    )
    print client.get_user('username')
    print client.get_team('team_name')
    print client.get_oncall_now('team_name', role='primary')
    print client.get('http://localhost:5000/api/v0/events?team=example_team&role=primary').json()


Test
----

.. code-block:: bash

    pip install tox
    tox


Release
-------

.. code-block:: bash

   python setup.py sdist
   twine upload dist/*
