# -*- coding: utf-8 -*-
"""cas_provider.signals -- signal definitions for cas_provider
"""
from django import dispatch


on_cas_collect_histories = dispatch.Signal(providing_args=["for_email"])