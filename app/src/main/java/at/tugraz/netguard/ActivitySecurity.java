package at.tugraz.netguard;

// ACN Task 2

import android.Manifest;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.app.ActivityCompat;
import android.support.v4.widget.SwipeRefreshLayout;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.SearchView;
import android.support.v7.widget.SwitchCompat;
import android.util.Log;
import android.util.TypedValue;
import android.view.MenuItem;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.TextView;

import java.util.List;

import eu.faircode.netguard.DatabaseHelper;
import eu.faircode.netguard.R;
import eu.faircode.netguard.Rule;
import eu.faircode.netguard.ServiceSinkhole;
import eu.faircode.netguard.Util;

public class ActivitySecurity extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener, ActivityCompat.OnRequestPermissionsResultCallback {
    private static final String TAG = "NetGuard.Security";
    private static final int PHONE_REQUEST_CODE = 123;

    private boolean running = false;

    private boolean resolve;
    private boolean organization;

    private SwipeRefreshLayout swipeRefresh;
    private AdapterSecurity adapter;
    private MenuItem menuSearch = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.securitymonitoring);
        running = true;

        // set context of ACN utils
        ACNUtils.context = this;

        // Action bar
        View actionView = getLayoutInflater().inflate(R.layout.actionsecurity, null, false);
        SwitchCompat swEnabled = actionView.findViewById(R.id.swEnabled);

        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(actionView);

        getSupportActionBar().setTitle(R.string.menu_security);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // Get settings
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        resolve = prefs.getBoolean("resolve", false);
        organization = prefs.getBoolean("organization", false);
        boolean security = prefs.getBoolean("security", false);

        // get permission to extract imei and number (api level > 23)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.READ_PHONE_STATE}, PHONE_REQUEST_CODE);
        }
        else
        {
            ACNUtils.enableSecurityAnalysis(security);
            ACNUtils.setIMEI(ACNUtils.getIMEI());
        }

        // Show disabled message
        TextView tvDisabled = findViewById(R.id.tvDisabled);
        tvDisabled.setVisibility(security ? View.GONE : View.VISIBLE);

        // Set enabled switch
        swEnabled.setChecked(security);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean("security", isChecked).apply();
                ACNUtils.enableSecurityAnalysis(isChecked);
            }
        });

        // Listen for preference changes
        prefs.registerOnSharedPreferenceChangeListener(this);

        // Application list
        RecyclerView rvApplication = findViewById(R.id.rvApplication);
        rvApplication.setHasFixedSize(true);
        rvApplication.setLayoutManager(new LinearLayoutManager(this));
        adapter = new AdapterSecurity(this);
        rvApplication.setAdapter(adapter);

        // Swipe to refresh
        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        swipeRefresh = findViewById(R.id.swipeRefresh);
        swipeRefresh.setColorSchemeColors(Color.WHITE, Color.WHITE, Color.WHITE);
        swipeRefresh.setProgressBackgroundColorSchemeColor(tv.data);
        swipeRefresh.setVisibility(security ? View.VISIBLE : View.GONE);
        swipeRefresh.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() {
            @Override
            public void onRefresh() {
                Rule.clearCache(ActivitySecurity.this);
                ServiceSinkhole.reload("pull", ActivitySecurity.this, false);
                updateApplicationList(null);
            }
        });

        // Fill application list
        updateApplicationList(getIntent().getStringExtra(null));
    }

    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults)
    {
        if (requestCode == PHONE_REQUEST_CODE) {
            Log.i(TAG, "READ_PHONE_STATE was granted: " + (grantResults[0] == PackageManager.PERMISSION_GRANTED));

            ACNUtils.enableSecurityAnalysis(true);
            ACNUtils.setIMEI(ACNUtils.getIMEI());
        }
    }

    private void updateApplicationList(final String search) {
        Log.i(TAG, "Update search=" + search);

        new AsyncTask<Object, Object, List<Rule>>() {
            private boolean refreshing = true;

            @Override
            protected void onPreExecute() {
                swipeRefresh.post(new Runnable() {
                    @Override
                    public void run() {
                        if (refreshing)
                            swipeRefresh.setRefreshing(true);
                    }
                });
            }

            @Override
            protected List<Rule> doInBackground(Object... arg) {
                return Rule.getRules(false, ActivitySecurity.this);
            }

            @Override
            protected void onPostExecute(List<Rule> result) {
                if (running) {
                    if (adapter != null) {
                        adapter.set(result);
                        updateSearch(search);
                    }

                    if (swipeRefresh != null) {
                        refreshing = false;
                        swipeRefresh.setRefreshing(false);
                    }
                }
            }
        }.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }

    private void updateSearch(String search) {
        if (menuSearch != null) {
            SearchView searchView = (SearchView) menuSearch.getActionView();
            if (search == null) {
                if (menuSearch.isActionViewExpanded())
                    adapter.getFilter().filter(searchView.getQuery().toString());
            } else {
                menuSearch.expandActionView();
                searchView.setQuery(search, true);
            }
        }
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        Log.i(TAG, "Preference " + name + "=" + prefs.getAll().get(name));
        if ("security".equals(name)) {
            // Get enabled
            boolean security = prefs.getBoolean(name, false);

            // Display disabled warning
            TextView tvDisabled = findViewById(R.id.tvDisabled);
            tvDisabled.setVisibility(security ? View.GONE : View.VISIBLE);
            swipeRefresh.setVisibility(security ? View.VISIBLE : View.GONE);

            // Check switch state
            SwitchCompat swEnabled = getSupportActionBar().getCustomView().findViewById(R.id.swEnabled);
            if (swEnabled.isChecked() != security)
                swEnabled.setChecked(security);

            ServiceSinkhole.reload("changed " + name, ActivitySecurity.this, false);
        }
    }

    private DatabaseHelper.ConnectionChangedListener connectionChangedListener = new DatabaseHelper.ConnectionChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (adapter != null && adapter.isLive())
                        adapter.notifyDataSetChanged();
                }
            });
        }
    };

    private DatabaseHelper.KeywordChangedListener keywordChangedListener = new DatabaseHelper.KeywordChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (adapter != null && adapter.isLive())
                        adapter.notifyDataSetChanged();
                }
            });
        }
    };

    @Override
    protected void onResume() {
        Log.i(TAG, "Resume");

        DatabaseHelper.getInstance(this).addKeywordChangedListener(keywordChangedListener);

        DatabaseHelper.getInstance(this).addConnectionChangedListener(connectionChangedListener);
        if (adapter != null)
            adapter.notifyDataSetChanged();

        super.onResume();
    }

    @Override
    protected void onPause() {
        Log.i(TAG, "Pause");
        super.onPause();

        DatabaseHelper.getInstance(this).removeKeywordChangedListener(keywordChangedListener);
        DatabaseHelper.getInstance(this).removeConnectionChangedListener(connectionChangedListener);
    }
}
