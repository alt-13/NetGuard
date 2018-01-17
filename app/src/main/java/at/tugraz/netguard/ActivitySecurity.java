package at.tugraz.netguard;

// ACN Task 2

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
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
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ImageSpan;
import android.util.Log;
import android.util.TypedValue;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

import eu.faircode.netguard.ActivityPro;
import eu.faircode.netguard.DatabaseHelper;
import eu.faircode.netguard.IAB;
import eu.faircode.netguard.R;
import eu.faircode.netguard.Rule;
import eu.faircode.netguard.ServiceSinkhole;
import eu.faircode.netguard.Util;

public class ActivitySecurity extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener, ActivityCompat.OnRequestPermissionsResultCallback {
    private static final String TAG = "NetGuard.Security";
    private static final int PHONE_REQUEST_CODE = 123;

    private boolean running = false;
    private SwitchCompat swEnabled;

    private static final int MIN_SDK = Build.VERSION_CODES.LOLLIPOP_MR1;

    private boolean resolve;
    private boolean organization;

    private SwipeRefreshLayout swipeRefresh;
    private AdapterSecurity adapter;
    private MenuItem menuSearch = null;

    private static final int REQUEST_LOGCAT = 3;

    public static final String EXTRA_REFRESH = "Refresh";
    public static final String EXTRA_SEARCH = "Search";
    public static final String EXTRA_RELATED = "Related";
    public static final String EXTRA_APPROVE = "Approve";
    public static final String EXTRA_LOGCAT = "Logcat";


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
            ACNUtils.prepareNativeSide(this);
            ACNUtils.enableSecurityAnalysis(security);
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

    @Override
    protected void onNewIntent(Intent intent) {
        Log.i(TAG, "New intent");
        Util.logExtras(intent);
        super.onNewIntent(intent);

        if (Build.VERSION.SDK_INT < MIN_SDK || Util.hasXposed(this))
            return;

        setIntent(intent);

        if (Build.VERSION.SDK_INT >= MIN_SDK) {
            if (intent.hasExtra(EXTRA_REFRESH))
                updateApplicationList(intent.getStringExtra(EXTRA_SEARCH));
            else
                updateSearch(intent.getStringExtra(EXTRA_SEARCH));
            checkExtras(intent);
        }
    }

    private void checkExtras(Intent intent) {
        // Approve request
        if (intent.hasExtra(EXTRA_APPROVE)) {
            Log.i(TAG, "Requesting VPN approval");
            swEnabled.toggle();
        }

        if (intent.hasExtra(EXTRA_LOGCAT)) {
            Log.i(TAG, "Requesting logcat");
            Intent logcat = getIntentLogcat();
            if (logcat.resolveActivity(getPackageManager()) != null)
                startActivityForResult(logcat, REQUEST_LOGCAT);
        }
    }

    private Intent getIntentLogcat() {
        Intent intent;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
            if (Util.isPackageInstalled("org.openintents.filemanager", this)) {
                intent = new Intent("org.openintents.action.PICK_DIRECTORY");
            } else {
                intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("https://play.google.com/store/apps/details?id=org.openintents.filemanager"));
            }
        } else {
            intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TITLE, "logcat.txt");
        }
        return intent;
    }

    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults)
    {
        if (requestCode == PHONE_REQUEST_CODE) {
            Log.i(TAG, "READ_PHONE_STATE was granted: " + (grantResults[0] == PackageManager.PERMISSION_GRANTED));

            ACNUtils.prepareNativeSide(this);
            ACNUtils.enableSecurityAnalysis(true);
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

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        if (Build.VERSION.SDK_INT < MIN_SDK)
            return false;

        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.security, menu);

        // Search
        menuSearch = menu.findItem(R.id.menu_search);
        menuSearch.setOnActionExpandListener(new MenuItem.OnActionExpandListener() {
            @Override
            public boolean onMenuItemActionExpand(MenuItem item) {
                return true;
            }

            @Override
            public boolean onMenuItemActionCollapse(MenuItem item) {
                if (getIntent().hasExtra(EXTRA_SEARCH) && !getIntent().getBooleanExtra(EXTRA_RELATED, false))
                    finish();
                return true;
            }
        });

        final SearchView searchView = (SearchView) menuSearch.getActionView();
        searchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override
            public boolean onQueryTextSubmit(String query) {
                if (adapter != null)
                    adapter.getFilter().filter(query);
                searchView.clearFocus();
                return true;
            }

            @Override
            public boolean onQueryTextChange(String newText) {
                if (adapter != null)
                    adapter.getFilter().filter(newText);
                return true;
            }
        });
        searchView.setOnCloseListener(new SearchView.OnCloseListener() {
            @Override
            public boolean onClose() {
                Intent intent = getIntent();
                intent.removeExtra(EXTRA_SEARCH);

                if (adapter != null)
                    adapter.getFilter().filter(null);
                return true;
            }
        });
        String search = getIntent().getStringExtra(EXTRA_SEARCH);
        if (search != null) {
            menuSearch.expandActionView();
            searchView.setQuery(search, true);
        }

        markPro(menu.findItem(R.id.menu_log), ActivityPro.SKU_LOG);
        if (!IAB.isPurchasedAny(this))
            markPro(menu.findItem(R.id.menu_pro), null);

        if (!Util.hasValidFingerprint(this) || getIntentInvite(this).resolveActivity(getPackageManager()) == null)
            menu.removeItem(R.id.menu_invite);

        if (getIntentSupport().resolveActivity(getPackageManager()) == null)
            menu.removeItem(R.id.menu_support);

        return true;
    }

    private void markPro(MenuItem menu, String sku) {
        if (sku == null || !IAB.isPurchased(sku, this)) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            boolean dark = prefs.getBoolean("dark_theme", false);
            SpannableStringBuilder ssb = new SpannableStringBuilder("  " + menu.getTitle());
            ssb.setSpan(new ImageSpan(this, dark ? R.drawable.ic_shopping_cart_white_24dp : R.drawable.ic_shopping_cart_black_24dp), 0, 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            menu.setTitle(ssb);
        }
    }

    private static Intent getIntentInvite(Context context) {
        Intent intent = new Intent("com.google.android.gms.appinvite.ACTION_APP_INVITE");
        intent.setPackage("com.google.android.gms");
        intent.putExtra("com.google.android.gms.appinvite.TITLE", context.getString(R.string.menu_invite));
        intent.putExtra("com.google.android.gms.appinvite.MESSAGE", context.getString(R.string.msg_try));
        intent.putExtra("com.google.android.gms.appinvite.BUTTON_TEXT", context.getString(R.string.msg_try));
        // com.google.android.gms.appinvite.DEEP_LINK_URL
        return intent;
    }

    private static Intent getIntentSupport() {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(Uri.parse("https://github.com/M66B/NetGuard/blob/master/FAQ.md"));
        return intent;
    }

    private DatabaseHelper.KeywordChangedListener keywordChangedListener = new DatabaseHelper.KeywordChangedListener() {
        @Override
        public void onChanged(final int uid) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    // update adapter
                    if (adapter != null && adapter.isLive())
                        adapter.notifyDataSetChanged();

                    //update native code keywords array
                    Cursor cursor = DatabaseHelper.getInstance(ActivitySecurity.this).getKeywords(uid);
                    final int colKeywords = cursor.getColumnIndex("keyword");
                    final int colRegex = cursor.getColumnIndex("is_regex");
                    List<String> keywords = new ArrayList<String>();
                    List<Integer> isRegex = new ArrayList<Integer>();

                    cursor.moveToFirst();
                    while(!cursor.isAfterLast()) {
                        String keyword = cursor.getString(colKeywords);

                        if (!keyword.equals(ActivitySecurity.this.getResources().getString(R.string.keyword_imei)) &&
                                !keyword.equals(ActivitySecurity.this.getResources().getString(R.string.keyword_phone_number)) &&
                                !keyword.equals(ActivitySecurity.this.getResources().getString(R.string.keyword_imsi))) {

                            keywords.add(keyword);
                            isRegex.add(cursor.getInt(colRegex));
                        }
                        cursor.moveToNext();
                    }

                    // transform to int array, because java.lang.Integer in C is more complicated...
                    int[] isRegexArray = new int[isRegex.size()];
                    for (int i = 0; i < isRegexArray.length; i++)
                        isRegexArray[i] = isRegex.get(i);

                    ACNUtils.updateKeywords(uid, keywords.toArray(new String[0]), isRegexArray);

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
