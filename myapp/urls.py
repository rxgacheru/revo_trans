from django.urls import path
from. import views
from .views import contact


urlpatterns = [
    path('api/admin-only/', views.AdminOnlyView.as_view()),
    path('api/staff-only/', views.StaffOnlyView.as_view()),
    path('api/users/', views.UserListCreateView.as_view(), name='user-list-create'),
    path('api/login/', views.ObtainTokenPairWithRoleView.as_view(), name="token_obtain_pair"),
    path('api/login/<int:pk>/', views.ObtainTokenPairWithRoleView.as_view(), name="token_obtain_pair"),
    path('password-reset/', views.PasswordResetRequestView.as_view()),
    path('password-reset-confirm/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('api/buses/', views.BusList.as_view()),
    path('api/buses/<pk>/', views.BusDetail.as_view()),
    path('api/routes/', views.RouteListCreate.as_view()),
    path('api/routes/<pk>/', views.RouteRetrieveUpdateDestroy.as_view()),
    path('api/bookings/', views.BookingListView.as_view()),
    path('api/bookings/<pk>/', views.BookingDetailView.as_view()),
    path('api/bookings/', views.BookingCreateView.as_view()),

    path('api/bus-expenditures/', views.BusExpenditureListCreateView.as_view()),
    path('api/bus-expenditures/<pk>/', views.BusExpenditureRetrieveUpdateDestroyView.as_view()),
    path('api/bus-reviews/', views.BusReviewListCreateView.as_view()),
    path('api/bus-reviews/<pk>/', views.BusReviewRetrieveUpdateDestroyView.as_view()),
    path('api/expenditures/', views.ExpenditureList.as_view()),
    path('api/expenditures/<pk>/', views.ExpenditureDetail.as_view()),
    path('api/contact/', contact, name='contact'),
    path('api/contacts/', views.ContactListView.as_view()),
    path('api/contacts/create/', views.ContactCreateView.as_view()),

]

