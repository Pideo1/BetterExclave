/******************************************************************************
 *                                                                            *
 * Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>             *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.ui.profile

import android.os.Bundle
import android.text.InputType
import android.view.View
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import io.nekohasekai.sagernet.databinding.LayoutAwgAutotuneBinding
import io.nekohasekai.sagernet.databinding.LayoutAwgAutotuneRowBinding
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import java.util.concurrent.atomic.AtomicReference
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.bg.AutoFailover
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreference
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.fmt.wireguard.AmneziaWG
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.unwrapIDN

class WireGuardSettingsActivity : ProfileSettingsActivity<WireGuardBean>() {

    override fun createEntity() = WireGuardBean()

    override fun WireGuardBean.init() {
        DataStore.profileName = name

        DataStore.serverLocalAddress = localAddress
        DataStore.serverPrivateKey = privateKey

        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort

        DataStore.serverCertificates = peerPublicKey
        DataStore.serverPassword = peerPreSharedKey

        DataStore.serverMTU = mtu
        DataStore.serverWireGuardReserved = reserved
        DataStore.serverAwgEnabled = AmneziaWG.isEnabled(amnezia)
        val awg = AmneziaWG.parseAll(amnezia)
        for (key in AmneziaWG.uapiKeys) {
            DataStore.profileCacheStore.putString(Key.SERVER_AWG_PREFIX + key, awg[key] ?: "")
        }
        DataStore.serverWireGuardKeepaliveInterval = keepaliveInterval
    }

    override fun WireGuardBean.serialize() {
        name = DataStore.profileName

        localAddress = DataStore.serverLocalAddress
        privateKey = DataStore.serverPrivateKey

        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort

        peerPublicKey = DataStore.serverCertificates
        peerPreSharedKey = DataStore.serverPassword

        mtu = DataStore.serverMTU
        reserved = DataStore.serverWireGuardReserved
        amnezia = AmneziaWG.build(
            AmneziaWG.uapiKeys.associateWith { DataStore.profileCacheStore.getString(Key.SERVER_AWG_PREFIX + it, "")!!.trim() },
            DataStore.serverAwgEnabled,
        )
        keepaliveInterval = DataStore.serverWireGuardKeepaliveInterval
    }

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.wireguard_preferences)
        createAmneziaPreferences()
        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }
        findPreference<EditTextPreference>(Key.SERVER_PASSWORD)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
        findPreference<EditTextPreference>(Key.SERVER_PRIVATE_KEY)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
        findPreference<EditTextPreference>(Key.SERVER_MTU)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        findPreference<EditTextPreference>(Key.SERVER_WIREGUARD_KEEPALIVE_INTERVAL)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
    }

    private fun PreferenceFragmentCompat.createAmneziaPreferences() {
        val category = findPreference<PreferenceCategory>(Key.SERVER_AWG_CATEGORY)!!
        val context = category.context
        category.addPreference(SwitchPreference(context).apply {
            key = Key.SERVER_AWG_ENABLED
            setTitle(R.string.awg_enable)
            setSummary(R.string.awg_enable_sum)
            setIcon(R.drawable.ic_baseline_security_24)
        })
        val fields = AmneziaWG.uapiKeys.associateWith { key ->
            EditTextPreference(context).apply {
                this.key = Key.SERVER_AWG_PREFIX + key
                title = AmneziaWG.confKey(key)
                dialogTitle = title
                setIcon(R.drawable.ic_baseline_tune_24)
                // I1-I5 are kilobytes of hex, keep the summary to one glance
                summaryProvider = Preference.SummaryProvider<EditTextPreference> { pref ->
                    pref.text.orEmpty().let { if (it.length > 48) it.take(48) + "…" else it }
                }
                if (key in numericKeys) {
                    setOnBindEditTextListener { it.inputType = InputType.TYPE_CLASS_NUMBER }
                } else {
                    setOnBindEditTextListener(EditTextPreferenceModifiers.Monospace)
                }
            }
        }
        category.addPreference(Preference(context).apply {
            setTitle(R.string.awg_randomize)
            setSummary(R.string.awg_randomize_sum)
            setIcon(R.drawable.ic_baseline_cached)
            setOnPreferenceClickListener {
                // setting text goes through the data store and refreshes the summary
                AmneziaWG.randomJunk().forEach { (key, value) -> fields[key]?.text = value }
                true
            }
        })
        category.addPreference(Preference(context).apply {
            setTitle(R.string.awg_autotune)
            summary = getString(R.string.awg_autotune_sum, AUTOTUNE_VARIANTS)
            setIcon(R.drawable.ic_baseline_tune_24)
            setOnPreferenceClickListener {
                autoTune(fields)
                true
            }
        })
        fields.values.forEach { category.addPreference(it) }
        category.children().forEach { if (it.key != Key.SERVER_AWG_ENABLED) it.dependency = Key.SERVER_AWG_ENABLED }
        // switch, randomize, auto-tune, Jc..H4; I1-I5 and the AWG 3.x keys go under "Advanced"
        category.initialExpandedChildrenCount = 3 + AmneziaWG.uapiKeys.indexOf("i1")
    }

    /** One auto-tune candidate: AmneziaWG keys to override ("" removes the key) and an optional MTU. */
    private class Variant(val overrides: Map<String, String>, val i1Name: String? = null, val mtu: Int? = null) {
        val label: String
            get() = buildList {
                if ("jc" in overrides || "jmin" in overrides || "jmax" in overrides) {
                    add("Jc=${overrides["jc"] ?: "-"} Jmin=${overrides["jmin"] ?: "-"} Jmax=${overrides["jmax"] ?: "-"}")
                }
                i1Name?.let { add("I1=$it") }
                mtu?.let { add("MTU=$it") }
            }.joinToString(" ").ifEmpty { "current" }
    }

    /**
     * Tries the current and [AUTOTUNE_VARIANTS] random junk settings through real connections and offers
     * the fastest one that worked. If none of them connects, a second step keeps the junk settings and
     * tries I1 signature packets imitating other protocols, combined with smaller MTUs; after that the
     * user can keep trying random combinations of all three until one connects. Everything tried here
     * is client-side only; S1-S4 and H1-H4 must match the server and are never touched.
     */
    private fun PreferenceFragmentCompat.autoTune(fields: Map<String, EditTextPreference>) {
        val activity = requireActivity()
        val base = createEntity().applyDefaultValues().apply { serialize() }
        val params = AmneziaWG.parseAll(base.amnezia)
        val junkKeys = AmneziaWG.randomJunk().keys
        val mtus = listOf(base.mtu, 1420, 1380, 1280).distinct()
        fun signature(name: String) = mapOf(
            "i1" to AmneziaWG.signaturePresets[name]!!, "i2" to "", "i3" to "", "i4" to "", "i5" to "",
        )

        val junkStep = listOf(Variant(params.filterKeys { it in junkKeys })) +
            List(AUTOTUNE_VARIANTS) { Variant(AmneziaWG.randomJunk()) }
        val signatureStep = AmneziaWG.signaturePresets.keys.flatMap { name ->
            listOf(base.mtu, 1380, 1280).distinct().map { Variant(signature(name), name, it) }
        }
        fun randomVariant(): Variant {
            val name = AmneziaWG.signaturePresets.keys.random()
            return Variant(AmneziaWG.randomJunk() + signature(name), name, mtus.random())
        }

        val ui = LayoutAwgAutotuneBinding.inflate(activity.layoutInflater)
        ui.logScroll.layoutParams.height = (resources.displayMetrics.heightPixels * 0.3).toInt()
        val dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.awg_autotune)
            .setView(ui.root)
            .setNegativeButton(R.string.awg_autotune_stop, null)
            .setNeutralButton(R.string.awg_autotune_keep_trying, null)
            .setPositiveButton(R.string.awg_autotune_apply, null)
            .setCancelable(false)
            .show()
        val stopButton = dialog.getButton(AlertDialog.BUTTON_NEGATIVE)
        val keepTryingButton = dialog.getButton(AlertDialog.BUTTON_NEUTRAL).apply { isVisible = false }
        val applyButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE).apply { isEnabled = false }

        // written on the main thread, read by the workers to know when to stop
        val best = AtomicReference<Pair<Variant, Int>?>(null)
        var ok = 0
        var failed = 0
        var job: Job? = null

        fun updateCounters() {
            ui.countOk.text = "✓ $ok"
            ui.countFail.text = "✗ $failed"
            ui.countTotal.text = getString(R.string.awg_autotune_tested, ok + failed)
        }

        fun stage(title: Int, steps: Int?) {
            ui.status.setText(title)
            ui.progress.isVisible = true
            if (steps == null) {
                ui.progress.isIndeterminate = true
            } else {
                ui.progress.isIndeterminate = false
                ui.progress.max = steps
                ui.progress.setProgressCompat(0, false)
            }
        }

        fun addResult(variant: Variant, ping: Int) {
            if (ping > 0) ok++ else failed++
            updateCounters()
            val row = LayoutAwgAutotuneRowBinding.inflate(activity.layoutInflater, ui.log, false)
            val color = ContextCompat.getColor(activity, if (ping > 0) R.color.material_green_600 else R.color.material_red_400)
            row.mark.text = if (ping > 0) "✓" else "✗"
            row.mark.setTextColor(color)
            row.label.text = variant.label
            row.result.text = if (ping > 0) "$ping ms" else "fail"
            row.result.setTextColor(color)
            ui.log.addView(row.root)
            while (ui.log.childCount > AUTOTUNE_MAX_ROWS) ui.log.removeViewAt(0)
            ui.logScroll.post { ui.logScroll.fullScroll(View.FOCUS_DOWN) }
            if (!ui.progress.isIndeterminate) ui.progress.setProgressCompat(ui.progress.progress + 1, true)

            if (ping > 0 && ping < (best.get()?.second ?: Int.MAX_VALUE)) {
                best.set(variant to ping)
                ui.bestCard.isVisible = true
                ui.bestTitle.text = getString(R.string.awg_autotune_best, ping)
                ui.bestValue.text = variant.label
                applyButton.isEnabled = true
            }
        }

        fun finished(title: Int) {
            ui.status.setText(title)
            ui.progress.isVisible = false
            stopButton.setText(R.string.awg_autotune_close)
            keepTryingButton.isVisible = best.get() == null
        }

        suspend fun test(variant: Variant) {
            val bean = base.clone().apply {
                amnezia = AmneziaWG.build((params + variant.overrides).filterValues { it.isNotEmpty() }, true)
                variant.mtu?.let { mtu = it }
            }
            val ping = AutoFailover.ping(ProxyEntity().putBean(bean))
            withContext(Dispatchers.Main) { addResult(variant, ping) }
        }

        suspend fun runStep(variants: List<Variant>) = coroutineScope {
            val semaphore = Semaphore(AUTOTUNE_CONCURRENCY)
            variants.map { async { semaphore.withPermit { test(it) } } }.awaitAll()
        }

        fun start(endless: Boolean) {
            stopButton.setText(R.string.awg_autotune_stop)
            keepTryingButton.isVisible = false
            job = activity.lifecycleScope.launch(Dispatchers.Default) {
                if (!endless) {
                    withContext(Dispatchers.Main) { stage(R.string.awg_autotune_stage_junk, junkStep.size) }
                    runStep(junkStep)
                    if (best.get() == null) {
                        withContext(Dispatchers.Main) { stage(R.string.awg_autotune_stage_signature, signatureStep.size) }
                        runStep(signatureStep)
                    }
                } else {
                    withContext(Dispatchers.Main) { stage(R.string.awg_autotune_stage_endless, null) }
                    // runs until something connects or the user stops it
                    coroutineScope {
                        repeat(AUTOTUNE_CONCURRENCY) {
                            launch { while (isActive && best.get() == null) test(randomVariant()) }
                        }
                    }
                }
                withContext(Dispatchers.Main) {
                    finished(if (best.get() != null) R.string.awg_autotune_found else R.string.awg_autotune_nothing)
                }
            }
        }

        stopButton.setOnClickListener {
            if (job?.isActive == true) {
                job?.cancel()
                finished(R.string.awg_autotune_stopped)
            } else {
                dialog.dismiss()
            }
        }
        keepTryingButton.setOnClickListener { start(endless = true) }
        applyButton.setOnClickListener {
            best.get()?.first?.let { variant ->
                variant.overrides.forEach { (key, value) -> fields[key]?.text = value }
                variant.mtu?.let { findPreference<EditTextPreference>(Key.SERVER_MTU)?.text = it.toString() }
            }
            findPreference<SwitchPreference>(Key.SERVER_AWG_ENABLED)?.isChecked = true
            dialog.dismiss()
        }
        dialog.setOnDismissListener { job?.cancel() }

        updateCounters()
        start(endless = false)
    }

    private fun PreferenceCategory.children() = (0 until preferenceCount).map { getPreference(it) }

    private val numericKeys = setOf("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")

    companion object {
        private const val AUTOTUNE_VARIANTS = 11
        private const val AUTOTUNE_CONCURRENCY = 3
        private const val AUTOTUNE_MAX_ROWS = 200
    }

}