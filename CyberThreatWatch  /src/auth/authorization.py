from supabase import create_client
import streamlit as st

class RoleBasedAuthorization:
    ROLES = {
        'admin': ['manage_users', 'view_logs', 'edit_config'],
        'analyst': ['view_reports', 'export_data'],
        'user': ['view_dashboard']
    }

    def __init__(self):
        self.client = create_client(
            st.secrets["SUPABASE_URL"],
            st.secrets["SUPABASE_KEY"]
        )
    
    def check_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has specific permission"""
        role = self._get_user_role(user_id)
        return permission in self.ROLES.get(role, [])
    
    def list_users(self):
        """Get all users with roles"""
        return self.client.table('users') \
            .select('id, email, role, created_at') \
            .execute() \
            .data
    
    def update_users(self, user_data):
        """Bulk update user roles"""
        self.client.table('users') \
            .upsert(user_data) \
            .execute()
    
    def _get_user_role(self, user_id: str) -> str:
        """Fetch user role from database"""
        res = self.client.table('users') \
            .select('role') \
            .eq('id', user_id) \
            .single() \
            .execute()
        return res.data.get('role', 'user')